"""Workspace selection, device IAM assignments, and resource-specific tokens."""
from dataclasses import dataclass
from datetime import timedelta
import time

import jwt
from django.conf import settings
from django.db import transaction
from drf_yasg.utils import swagger_auto_schema
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import AccessToken

from audit_logging.models import AuditLog
from iam.models import Role, Permission, DeviceRole, DevicePermission
from iam.effective import effective_access, RESOURCE_PERMISSIONS
from .models import DeviceRegistration
from .device_context import active_organization, active_context
from .device_security import tenant_workspaces, verify_tenant, device_token_registration, verify_dpop
from .device_serializers import DeviceContextSerializer, DeviceAccessSerializer, ResourceTokenSerializer
from .device_views import DeviceAPIView, _validated, _device_access_token


class DeviceContextView(DeviceAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        member = active_organization(request.user, manage=False)
        tenants = tenant_workspaces(request.user, member.organization)
        if member.active_tenant_id is None and len(tenants) == 1:
            member.active_tenant_id = tenants[0]['tenant_id']
            member.save(update_fields=['active_tenant_id'])
        active_ids = {row['tenant_id'] for row in tenants}
        return Response({'organization_id': str(member.organization_id), 'organization_name': member.organization.name,
                         'tenant_id': str(member.active_tenant_id) if member.active_tenant_id in active_ids else None,
                         'tenants': [{'tenant_id': str(row['tenant_id']), 'name': row['name']} for row in tenants]})

    @swagger_auto_schema(request_body=DeviceContextSerializer)
    def post(self, request):
        data = _validated(DeviceContextSerializer, request.data)
        member = active_organization(request.user, manage=False)
        verify_tenant(request.user, member.organization, data['tenant_id'])
        member = active_organization(request.user, member.organization_id, manage=False)
        member.active_tenant_id = data['tenant_id']
        member.save(update_fields=['active_tenant_id'])
        return Response({'organization_id': str(member.organization_id), 'tenant_id': str(member.active_tenant_id)})


def _device_for_context(request, device_id, *, lock=False):
    context = active_context(request.user)
    query = DeviceRegistration.objects.select_for_update() if lock else DeviceRegistration.objects
    device = query.filter(pk=device_id, organization=context.organization, tenant_id=context.active_tenant_id).first()
    if not device:
        raise NotFound('Device not found in your active workspace.')
    return device, context.organization


class DeviceAccessView(DeviceAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, device_id):
        device, organization = _device_for_context(request, device_id)
        direct = DevicePermission.objects.filter(device=device).first()
        roles, permissions = effective_access(device, organization, device=True)
        return Response({'device_id': str(device.pk), 'roles': roles, 'permissions': permissions,
                         'role_ids': list(device.role_assignments.values_list('role_id', flat=True)),
                         'permission_ids': list(direct.permissions.values_list('pk', flat=True)) if direct else [],
                         'role_catalog': list(Role.objects.filter(organization=organization).values('id', 'name')),
                         'permission_catalog': list(Permission.objects.filter(organization=organization).values('id', 'name'))})

    @swagger_auto_schema(request_body=DeviceAccessSerializer)
    @transaction.atomic
    def put(self, request, device_id):
        data = _validated(DeviceAccessSerializer, request.data)
        device, organization = _device_for_context(request, device_id, lock=True)
        roles = list(Role.objects.filter(pk__in=data['role_ids'], organization=organization).prefetch_related('permissions'))
        permissions = list(Permission.objects.filter(pk__in=data['permission_ids'], organization=organization))
        if len(roles) != len(set(data['role_ids'])) or len(permissions) != len(set(data['permission_ids'])):
            from rest_framework.exceptions import ValidationError
            raise ValidationError('All role_ids and permission_ids must exist in the active organization.')
        _, operator_permissions = effective_access(request.user, organization)
        if any(p.organization_id != organization.pk for role in roles for p in role.permissions.all()):
            raise PermissionDenied('Role contains permissions from another organization.')
        if organization.owner_id != request.user.pk:
            current_roles = set(device.role_assignments.values_list('role_id', flat=True))
            current_direct = set(Permission.objects.filter(devicepermission__device=device).values_list('pk', flat=True))
            if (current_roles != set(data['role_ids']) and 'organization.manage_roles' not in operator_permissions
                    or current_direct != set(data['permission_ids']) and 'organization.manage_permissions' not in operator_permissions):
                raise PermissionDenied('Role/permission assignment authority is required.')
            requested = {p.name for p in permissions}
            for role in roles:
                requested.update(p.name for p in role.permissions.all())
            if not requested.issubset(set(operator_permissions)):
                raise PermissionDenied('You may only delegate permissions you currently hold.')
        device.role_assignments.exclude(role_id__in=data['role_ids']).delete()
        for role in roles:
            DeviceRole.objects.get_or_create(device=device, role=role)
        direct, _ = DevicePermission.objects.get_or_create(device=device)
        direct.permissions.set(permissions)
        AuditLog.objects.create(user=request.user, action='device_access_updated', metadata={
            'device_id': str(device.pk), 'organization_id': str(organization.pk), 'tenant_id': str(device.tenant_id),
            'role_ids': [str(role.pk) for role in roles], 'permission_ids': [str(p.pk) for p in permissions]})
        return self.get(request, device_id)


@dataclass
class ResourceDevicePrincipal:
    registration: DeviceRegistration
    is_authenticated: bool = True

    @property
    def pk(self):
        return self.registration.pk


class ResourceSubjectAuthentication(BaseAuthentication):
    def authenticate_header(self, request):
        return 'Bearer'

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header:
            return None
        # Existing human login tokens are validated by SSO's configured JWT
        # authentication (some legacy tokens have no issuer/audience). The
        # resource token issued below always has explicit issuer and audience.
        if header[0].lower() == b'bearer':
            try:
                result = JWTAuthentication().authenticate(request)
                if result:
                    if result[1].get('principal_type', 'user') != 'user':
                        raise PermissionDenied('A human or device subject token is required.')
                    return result
            except AuthenticationFailed:
                pass
        try:
            if len(header) != 2 or header[0].lower() not in {b'bearer', b'dpop'}:
                raise ValueError('Invalid authorization header')
            raw = header[1].decode('ascii')
            claims = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'],
                                issuer=settings.DEVICE_TOKEN_ISSUER, options={'verify_aud': False,
                                'require': ['iss', 'exp', 'iat', 'token_type']})
        except (ValueError, jwt.PyJWTError) as exc:
            raise AuthenticationFailed('Invalid SSO subject token.') from exc
        if claims['token_type'] == 'device':
            device, verified = device_token_registration(raw, settings.DEVICE_ALLOWED_AUDIENCES)
            if header[0].lower() != (b'dpop' if device.public_key_thumbprint else b'bearer'):
                raise AuthenticationFailed('Authorization scheme must match the registered device key binding.')
            verify_dpop(request, device.public_key_thumbprint, access_token=raw)
            return ResourceDevicePrincipal(device), verified
        raise AuthenticationFailed('A human or device subject token is required.')


class ResourceTokenView(DeviceAPIView):
    authentication_classes = [ResourceSubjectAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=ResourceTokenSerializer, operation_summary='Issue a resource token using current SSO IAM grants')
    def post(self, request):
        audience = _validated(ResourceTokenSerializer, request.data)['audience']
        if audience == 'arna-commerce' and not isinstance(request.user, ResourceDevicePrincipal):
            raise PermissionDenied('This Commerce exchange requires a paired photobooth device token.')
        resource_permissions = RESOURCE_PERMISSIONS[audience]
        subject_exp = request.auth.get('exp') if request.auth is not None else None
        expires_in = min(settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES * 60,
                         max(0, subject_exp - int(time.time()))) if subject_exp is not None else settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES * 60
        if isinstance(request.user, ResourceDevicePrincipal):
            device = request.user.registration
            if audience == 'arna-commerce' and device.audience != 'photobooth-api':
                raise PermissionDenied('Commerce device checkout requires a photobooth device registration.')
            _, permissions = effective_access(device, device.organization, device=True)
            if not set(permissions) & resource_permissions:
                raise PermissionDenied(f'This device has no {audience} permissions. Assign an SSO role or permission first.')
            token = _device_access_token(device, audience=audience, subject_exp=subject_exp)
            kind = 'DPoP' if device.public_key_thumbprint else 'Bearer'
        else:
            context = active_context(request.user, manage=False)
            roles, permissions = effective_access(request.user, context.organization)
            owner = context.organization.owner_id == request.user.pk
            permissions = sorted(resource_permissions if owner else set(permissions) & resource_permissions)
            if not permissions:
                raise PermissionDenied(f'No {audience} permissions in this workspace.')
            access = AccessToken.for_user(request.user)
            access.set_exp(lifetime=timedelta(minutes=settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES))
            if subject_exp is not None:
                access['exp'] = min(access['exp'], subject_exp)
            access['iss'] = settings.DEVICE_TOKEN_ISSUER
            access['aud'] = audience
            access['principal_type'] = 'user'
            access['org_id'] = str(context.organization_id)
            access['organization_id'] = str(context.organization_id)
            access['tenant_id'] = str(context.active_tenant_id)
            access['roles'], access['permissions'], access['scopes'] = roles, permissions, permissions
            access['is_owner'] = owner
            token, kind = str(access), 'Bearer'
        return Response({'access_token': token, 'token_type': kind,
                         'expires_in': expires_in, 'audience': audience})
