from rest_framework import viewsets, serializers
from django.db.models import Q
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Role, Permission, UserRole, UserPermission
from .serializers import RoleSerializer, PermissionSerializer, UserRoleSerializer, UserPermissionSerializer
from .permissions import CanManageRoles, CanAssignRoles, CanAssignDirectPermissions

class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, CanManageRoles]

    @swagger_auto_schema(
        operation_description="Create a new role with optional permissions.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING, description='Role Name', example='HR Manager'),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description='Description', example='Can manage employee data'),
                'organization': openapi.Schema(type=openapi.TYPE_STRING, format='uuid', description='Organization ID (Optional for Global Roles)'),
                'permission_ids': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_STRING, format='uuid'),
                    description='List of Permission IDs',
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
        # LOGIC: Show Roles that are either:
        # 1. GLOBAL (organization is NULL)
        # 2. ORGANIZATION-SPECIFIC (organization matches user's *ACTIVE* membership)
        return Role.objects.filter(
            Q(organization__isnull=True) | 
            Q(organization__members__user=user, organization__members__is_session_active=True)
        ).distinct()


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new permission.",
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


class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated, CanAssignRoles]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return UserRole.objects.none()
        
        user = self.request.user
        # LOGIC: Only show assignments where the Role belongs to an Organization I am a member of (Active Session).
        return UserRole.objects.filter(
            organization_member__user=user,
            organization_member__is_session_active=True
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


class UserPermissionViewSet(viewsets.ModelViewSet):
    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerializer
    permission_classes = [IsAuthenticated, CanAssignDirectPermissions]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return UserPermission.objects.none()
        
        user = self.request.user
        # LOGIC: Only show permissions for my org members in my ACTIVE session.
        return UserPermission.objects.filter(
            organization_member__user=user,
            organization_member__is_session_active=True
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
