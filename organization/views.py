from rest_framework import viewsets, serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth.models import AnonymousUser
from django.db.models import Q
from django.db import transaction
from .models import Organization, OrganizationMember
from .serializers import OrganizationSerializer, OrganizationMemberSerializer
from iam.permissions import CanManageOrganizationMembers

class OrganizationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_queryset(self):
        # Handle Swagger schema generation where user is AnonymousUser
        if getattr(self, 'swagger_fake_view', False) or isinstance(self.request.user, AnonymousUser):
            return Organization.objects.none()
        
        user = self.request.user
        # Show Organizations where:
        # 1. User is the OWNER (Creator) OR MEMBER
        # 2. AND the user has an ACTIVE SESSION in that organization
        return Organization.objects.select_related('owner').prefetch_related(
            'members__user'
        ).filter(
            members__user=user,
            members__is_session_active=True
        ).distinct()

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


class OrganizationMemberViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, CanManageOrganizationMembers]
    serializer_class = OrganizationMemberSerializer

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or isinstance(self.request.user, AnonymousUser):
            return OrganizationMember.objects.none()
        
        user = self.request.user
        # Show members of the organization where the user currently has an ACTIVE SESSION
        return OrganizationMember.objects.select_related(
            'user', 'organization', 'organization__owner'
        ).filter(
            organization__members__user=user,
            organization__members__is_session_active=True
        ).distinct()

    def get_permissions(self):
        """
        Override permissions to allow users to switch session and view their own memberships
        without needing managerial permissions.
        """
        if self.action in ['switch_session', 'my_memberships']:
            return [IsAuthenticated()]
        return super().get_permissions()
    
    def perform_create(self, serializer):
        # Permission logic is now handled by CanManageOrganizationMembers
        # Ensure new memberships do not automatically become the active session
        serializer.save(is_session_active=False)

    @action(detail=True, methods=['post'], url_path='switch-session')
    @transaction.atomic
    def switch_session(self, request, pk=None):
        """
        Custom action to switch the user's active session to this organization.
        """
        # Note: We cannot use self.get_object() here if the queryset filters out inactive sessions!
        # Implementation Detail:
        # We need to fetch the membership explicitly regardless of session state, 
        # but STRICTLY ensure it belongs to the request.user.
        from django.shortcuts import get_object_or_404
        
        # 1. Fetch membership ensuring it belongs to the user (security check)
        membership = get_object_or_404(OrganizationMember, pk=pk, user=request.user)

        # 2. Atomic operation: Deactivate all other sessions and activate this one
        OrganizationMember.objects.filter(user=request.user).update(is_session_active=False)
        # Refresh membership to get latest data
        membership.refresh_from_db()
        membership.is_session_active = True
        membership.save(update_fields=['is_session_active'])

        # 3. Generate New Tokens
        # We MUST use our custom serializer to ensuring all claims (org_id, roles) are included.
        from authentication.serializers import MyTokenObtainPairSerializer
        
        # get_token() returns a RefreshToken object with our custom claims
        refresh = MyTokenObtainPairSerializer.get_token(request.user)

        return Response({
            "status": "Session switched to " + membership.organization.name,
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        })

    @action(detail=False, methods=['get'], url_path='mine')
    def my_memberships(self, request):
        """
        List ALL memberships for the current user (Active and Inactive).
        Use this to populate the "Switch Organization" dropdown.
        """
        memberships = OrganizationMember.objects.filter(user=request.user)
        serializer = self.get_serializer(memberships, many=True)
        return Response(serializer.data)

