from rest_framework import viewsets, serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth.models import AnonymousUser
from django.db.models import Q
from django.db import transaction
from django.shortcuts import get_object_or_404
from .models import Organization, OrganizationMember
from .serializers import OrganizationSerializer, OrganizationMemberSerializer
from iam.permissions import CanManageOrganizationMembers

class OrganizationMemberViewSet(viewsets.ModelViewSet):
    """
    Nested ViewSet for managing members of a specific organization.
    Accessible via: /api/organizations/{organization_pk}/members/
    
    Special behavior:
    - POST without payload: Switch active session to this organization
    - POST with payload: Create new member in this organization
    """
    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationMemberSerializer

    def get_permissions(self):
        """
        Override permissions:
        - Switch session (POST without payload): Only need IsAuthenticated
        - CRUD operations: Need CanManageOrganizationMembers
        """
        if self.action == 'create' and not self.request.data:
            # Switch session - only need authentication
            return [IsAuthenticated()]
        # CRUD operations - need manage members permission
        return [IsAuthenticated(), CanManageOrganizationMembers()]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or isinstance(self.request.user, AnonymousUser):
            return OrganizationMember.objects.none()
        
        # Get organization from URL parameter
        organization_pk = self.kwargs.get('organization_pk')
        if not organization_pk:
            return OrganizationMember.objects.none()
        
        # Verify user has access to this organization
        user = self.request.user
        organization = get_object_or_404(
            Organization.objects.filter(
                Q(owner=user) | Q(members__user=user)
            ).distinct(),
            pk=organization_pk
        )
        
        # Return members of this specific organization
        return OrganizationMember.objects.select_related(
            'user', 'organization', 'organization__owner'
        ).filter(organization=organization)

    def create(self, request, *args, **kwargs):
        """
        Handle POST to /api/organizations/{id}/members/
        - If no payload: Switch active session to this organization
        - If payload provided: Create new member
        """
        # Get organization from URL parameter
        organization_pk = self.kwargs.get('organization_pk')
        organization = get_object_or_404(Organization, pk=organization_pk)
        
        # Check if request has payload
        if not request.data or len(request.data) == 0:
            # No payload = Switch session
            return self._switch_session(request, organization)
        
        # Has payload = Create member
        return super().create(request, *args, **kwargs)

    def _switch_session(self, request, organization):
        """
        Switch active session to this organization.
        Called when POST /api/organizations/{id}/members/ with no payload.
        """
        user = request.user
        
        # Check if user is a member of this organization
        membership = OrganizationMember.objects.filter(
            user=user,
            organization=organization
        ).first()
        
        if not membership:
            return Response(
                {"error": "You are not a member of this organization"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Atomic operation: Deactivate all other sessions and activate this one
        with transaction.atomic():
            OrganizationMember.objects.filter(user=user).update(is_session_active=False)
            membership.refresh_from_db()
            membership.is_session_active = True
            membership.save(update_fields=['is_session_active'])

        # Generate New Tokens with updated org context
        from authentication.serializers import MyTokenObtainPairSerializer
        refresh = MyTokenObtainPairSerializer.get_token(user)

        return Response({
            "status": "Session switched to " + organization.name,
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }, status=status.HTTP_200_OK)

    def perform_create(self, serializer):
        # Get organization from URL parameter
        organization_pk = self.kwargs.get('organization_pk')
        organization = get_object_or_404(Organization, pk=organization_pk)
        
        # Ensure user has permission to add members to this organization
        user = self.request.user
        if organization.owner != user:
            # Check if user has manage_members permission
            from organization.models import OrganizationMember as OrgMember
            membership = OrgMember.objects.filter(user=user, organization=organization).first()
            if not membership:
                raise serializers.ValidationError("You don't have permission to add members to this organization.")
        
        # Set organization and ensure new memberships don't automatically become active session
        serializer.save(organization=organization, is_session_active=False)


class OrganizationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_queryset(self):
        # Handle Swagger schema generation where user is AnonymousUser
        if getattr(self, 'swagger_fake_view', False) or isinstance(self.request.user, AnonymousUser):
            return Organization.objects.none()
        
        user = self.request.user
        # Show Organizations where user is OWNER or MEMBER (all memberships, not just active session)
        # This allows user to see all organizations they belong to for switching
        return Organization.objects.select_related('owner').prefetch_related(
            'members__user'
        ).filter(
            Q(owner=user) | Q(members__user=user)
        ).distinct()

    @action(detail=False, methods=['get'], url_path='current')
    def current(self, request):
        """
        Get the current active organization for the authenticated user.
        GET /api/organizations/current/
        """
        user = request.user
        
        # Get active organization membership
        active_membership = OrganizationMember.objects.select_related(
            'organization', 'organization__owner'
        ).filter(
            user=user,
            is_session_active=True
        ).first()
        
        if not active_membership:
            return Response(
                {"error": "No active organization session found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = OrganizationSerializer(active_membership.organization, context={'request': request})
        return Response(serializer.data)

    @transaction.atomic
    def perform_create(self, serializer):
        user = self.request.user
        if 'owner' not in serializer.validated_data:
            org = serializer.save(owner=user)
        else:
            org = serializer.save()
        
        # AUTOMATICALLY CREATE MEMBERSHIP FOR OWNER
        member, created = OrganizationMember.objects.get_or_create(user=user, organization=org)
        
        # SET AS ACTIVE SESSION (atomic operation - deactivate others and activate this one)
        OrganizationMember.objects.filter(user=user).update(is_session_active=False)
        member.refresh_from_db()
        member.is_session_active = True
        member.save(update_fields=['is_session_active'])



