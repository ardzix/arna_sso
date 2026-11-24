from rest_framework import viewsets, serializers
from django.db import transaction
from django.db.models import Q
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Role, Permission, UserRole, UserPermission
from .serializers import RoleSerializer, PermissionSerializer, UserRoleSerializer, UserPermissionSerializer
from .permissions import CanManageRoles, CanAssignRoles, CanAssignDirectPermissions
from .bnk_access import FULL_ADMIN, PRODUCT_KEY as BNK_IAM_PRODUCT, full_admin_name, guard_legacy_role_write, lock_organization

class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, CanManageRoles]

    @swagger_auto_schema(
        operation_description="Create a new role with optional permissions. Organization is automatically set from active organization session (cannot be overridden).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING, description='Role Name', example='HR Manager'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Description', example='Can manage employee data'),
                'permission_ids': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_STRING, format='uuid'),
                    description='List of Permission IDs (must belong to active organization)',
                    example=['3fa85f64-5717-4562-b3fc-2c963f66afa6']
                ),
            },
            required=['name']
        )
    )

    def create(self, request, *args, **kwargs):
        # Validation for Organization Creation is handled by CanManageRoles permission
        return super().create(request, *args, **kwargs)

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Role.objects.none()
        
        user = self.request.user
        # LOGIC: Show only ORGANIZATION-SPECIFIC roles from user's *ACTIVE* organization
        # Include roles from organizations where user is OWNER or MEMBER (with active session)
        # No global roles - all roles are organization-specific
        return Role.objects.select_related('organization').prefetch_related(
            'permissions', 'organization__members'
        ).filter(
            Q(organization__owner=user) | 
            Q(organization__members__user=user, organization__members__is_session_active=True)
        ).distinct()

    @transaction.atomic
    def perform_create(self, serializer):
        from organization.models import OrganizationMember
        memberships = OrganizationMember.objects.filter(user=self.request.user, is_session_active=True)
        organization_id = memberships.values_list('organization_id', flat=True).first()
        organization = lock_organization(organization_id) if organization_id else None
        name = serializer.validated_data.get('name')
        if full_admin_name(name) and not memberships.select_for_update().filter(organization_id=organization_id).first():
            raise PermissionDenied('Your active organization has changed. Refresh and try again.')
        guard_legacy_role_write(self.request.user, organization, new_name=name)
        super().perform_create(serializer)

    @transaction.atomic
    def perform_update(self, serializer):
        role = serializer.instance
        organization = lock_organization(role.organization_id) if role.organization_id else None
        role.refresh_from_db(fields=['name'])
        guard_legacy_role_write(self.request.user, organization, role, serializer.validated_data.get('name'))
        super().perform_update(serializer)

    @transaction.atomic
    def perform_destroy(self, instance):
        organization = lock_organization(instance.organization_id) if instance.organization_id else None
        instance.refresh_from_db(fields=['name'])
        guard_legacy_role_write(self.request.user, organization, instance)
        super().perform_destroy(instance)


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, CanManageRoles]  # Same permission as managing roles

    @swagger_auto_schema(
        operation_description="Create a new permission. Organization is automatically set from active organization session (cannot be overridden).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING, description='Permission Name', example='user.create'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Description', example='Can create new users'),
            },
            required=['name']
        )
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Permission.objects.none()
        
        user = self.request.user
        # LOGIC: Show only ORGANIZATION-SPECIFIC permissions from user's organization
        # Include permissions from organizations where user is OWNER or MEMBER (with active session)
        # No global permissions - all permissions are organization-specific
        return Permission.objects.select_related('organization').filter(
            Q(organization__owner=user) | 
            Q(organization__members__user=user, organization__members__is_session_active=True)
        ).distinct()

    def guard_bnk_permission(self, permission):
        organization = lock_organization(permission.organization_id)
        if permission.roles.filter(product_management__product_key=BNK_IAM_PRODUCT).exists():
            raise PermissionDenied('This permission is used by a BNK role.')
        if (organization and organization.owner_id != self.request.user.pk
                and permission.roles.filter(organization=organization, name=FULL_ADMIN).exists()):
            raise PermissionDenied('Only the organization owner can manage Full Admin permissions.')

    @transaction.atomic
    def perform_update(self, serializer):
        self.guard_bnk_permission(serializer.instance)
        super().perform_update(serializer)

    @transaction.atomic
    def perform_destroy(self, instance):
        self.guard_bnk_permission(instance)
        super().perform_destroy(instance)


class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated, CanAssignRoles]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return UserRole.objects.none()
        
        user = self.request.user
        # LOGIC: Show all UserRole assignments in organizations where user is OWNER or has active session
        # Get active organization membership first
        from organization.models import OrganizationMember
        active_membership = OrganizationMember.objects.filter(
            user=user,
            is_session_active=True
        ).first()
        
        if not active_membership:
            return UserRole.objects.none()
        
        org = active_membership.organization
        
        # Return all UserRoles for members in the organization
        # Owner can see all, members can see all in their active organization
        return UserRole.objects.select_related(
            'organization_member', 'organization_member__user', 
            'organization_member__organization', 'role'
        ).filter(
            organization_member__organization=org
        ).distinct()

    @swagger_auto_schema(
        operation_description="Assign a role to an organization member.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'organization_member': openapi.Schema(type=openapi.TYPE_STRING, description='Organization Member UUID', example='3fa85f64-5717-4562-b3fc-2c963f66afa6'),
                'role': openapi.Schema(type=openapi.TYPE_STRING, description='Role UUID', example='3fa85f64-5717-4562-b3fc-2c963f66afa6'),
            },
            required=['organization_member', 'role']
        )
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    def guard_assignment_roles(self, roles):
        organization_ids = sorted({role.organization_id for role in roles if role.organization_id})
        organizations = {pk: lock_organization(pk) for pk in organization_ids}
        for role in roles:
            role.refresh_from_db(fields=['name'])
            guard_legacy_role_write(self.request.user, organizations.get(role.organization_id), role)

    @transaction.atomic
    def perform_create(self, serializer):
        self.guard_assignment_roles([serializer.validated_data['role']])
        super().perform_create(serializer)

    @transaction.atomic
    def perform_update(self, serializer):
        self.guard_assignment_roles([serializer.instance.role, serializer.validated_data.get('role', serializer.instance.role)])
        super().perform_update(serializer)

    @transaction.atomic
    def perform_destroy(self, instance):
        self.guard_assignment_roles([instance.role])
        super().perform_destroy(instance)


class UserPermissionViewSet(viewsets.ModelViewSet):
    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerializer
    permission_classes = [IsAuthenticated, CanAssignDirectPermissions]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return UserPermission.objects.none()
        
        user = self.request.user
        # LOGIC: Show all UserPermission assignments in organizations where user is OWNER or has active session
        # Get active organization membership first
        from organization.models import OrganizationMember
        active_membership = OrganizationMember.objects.filter(
            user=user,
            is_session_active=True
        ).first()
        
        if not active_membership:
            return UserPermission.objects.none()
        
        org = active_membership.organization
        
        # Return all UserPermissions for members in the organization
        # Owner can see all, members can see all in their active organization
        return UserPermission.objects.select_related(
            'organization_member', 'organization_member__user',
            'organization_member__organization'
        ).prefetch_related('permissions').filter(
            organization_member__organization=org
        ).distinct()

    @swagger_auto_schema(
        operation_description="Assign direct permissions to an organization member.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'organization_member': openapi.Schema(type=openapi.TYPE_STRING, description='Organization Member UUID', example='3fa85f64-5717-4562-b3fc-2c963f66afa6'),
                'permission_ids': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_STRING, format='uuid'),
                    description='List of Permission IDs',
                    example=['3fa85f64-5717-4562-b3fc-2c963f66afa6']
                ),
            },
            required=['organization_member']
        )
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
