"""Organization-scoped management for the BNK product's assignable permissions."""

from collections.abc import Mapping
import re
from uuid import UUID, uuid4

import jwt
from django.conf import settings
from django.core.paginator import EmptyPage, Paginator
from django.db import transaction
from django.db.models import Count, Prefetch, Q
from drf_yasg.utils import swagger_auto_schema
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, UnsupportedMediaType
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.utils.mediatypes import media_type_matches
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from audit_logging.models import AuditLog
from organization.models import OrganizationMember

from .bnk_access import APP_CLIENT, AUDIENCE, FULL_ADMIN, PRODUCT_KEY
from .bnk_access import active_bnk_admin, admin_assignments, full_admin_name, lock_organization
from .models import DeviceRole, Permission, ProductManagedRole, Role, UserRole


CATALOG = {
    'arnasite.cms.manage': 'website',
    'crm.read': 'crm', 'crm.write': 'crm', 'crm.manage': 'crm',
    'crm.inbox.read': 'crm', 'crm.inbox.write': 'crm',
    'operations.read': 'operations', 'operations.write': 'operations', 'operations.manage': 'operations',
    'business_hub:read': 'levelup', 'business_hub:write': 'levelup',
}
ROLE_LIMIT = 100


def canonical_id(value):
    try:
        parsed = UUID(value)
        if str(parsed) == value and parsed.int:
            return parsed
    except (TypeError, ValueError, AttributeError):
        pass


class BnkResourceAuthentication(JWTAuthentication):
    def get_validated_token(self, raw_token):
        try:
            claims = jwt.decode(
                raw_token, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'],
                audience=AUDIENCE, issuer=settings.DEVICE_TOKEN_ISSUER,
                options={'require': ['exp', 'iat', 'iss', 'aud', 'token_type'], 'strict_aud': True},
            )
        except (jwt.PyJWTError, TypeError, ValueError) as exc:
            raise AuthenticationFailed('A valid BNK IAM resource token is required.') from exc
        organization_id = canonical_id(claims.get('organization_id'))
        if (claims.get('principal_type') != 'user' or claims['token_type'] != 'resource_access'
                or claims.get('app_client_id') != APP_CLIENT
                or organization_id is None or claims.get('org_id') != str(organization_id)
                or canonical_id(claims.get('user_id')) is None):
            raise AuthenticationFailed('A valid BNK IAM human organization context is required.')
        return claims


class ObjectInput(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, Mapping) or set(data) - set(self.fields):
            raise serializers.ValidationError({'non_field_errors': ['Supply only the supported JSON fields.']})
        return super().to_internal_value(data)


class RoleInput(ObjectInput):
    name = serializers.CharField(max_length=120)
    description = serializers.CharField(max_length=500, allow_blank=True, required=False, default='')
    permission_codes = serializers.ListField(
        child=serializers.ChoiceField(choices=tuple(CATALOG)), max_length=len(CATALOG),
    )

    def validate_name(self, value):
        if full_admin_name(value):
            raise serializers.ValidationError('Full Admin is reserved.')
        return value

    def validate_permission_codes(self, value):
        return sorted(set(value))

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError('Supply at least one field.')
        return attrs


class CanonicalIdField(serializers.CharField):
    def to_internal_value(self, data):
        value = canonical_id(data)
        if value is None:
            raise serializers.ValidationError('A canonical UUID is required.')
        return value


class AssignmentInput(ObjectInput):
    role_ids = serializers.ListField(child=CanonicalIdField(), max_length=ROLE_LIMIT)


def managed_roles(organization_id):
    return Role.objects.filter(
        organization_id=organization_id, product_management__organization_id=organization_id,
        product_management__product_key=PRODUCT_KEY,
    ).exclude(name=FULL_ADMIN)


def visible_roles(organization_id):
    product = Q(product_management__organization_id=organization_id, product_management__product_key=PRODUCT_KEY)
    return Role.objects.filter(Q(name=FULL_ADMIN) | product, organization_id=organization_id)


def present_roles(roles, organization_id):
    return roles.annotate(member_count=Count(
        'userrole__organization_member', distinct=True,
        filter=Q(userrole__organization_member__organization_id=organization_id),
    )).prefetch_related(Prefetch('permissions', queryset=Permission.objects.filter(
        organization_id=organization_id, name__in=CATALOG,
    )))


def role_response(role):
    return {'id': str(role.pk), 'name': role.name, 'description': role.description,
            'permission_codes': sorted(permission.name for permission in role.permissions.all()),
            'locked': role.name == FULL_ADMIN, 'member_count': role.member_count}


def records_for_members(scoped_members, organization_id):
    assigned = UserRole.objects.filter(role__in=visible_roles(organization_id)).select_related('role')
    return scoped_members.select_related('user').prefetch_related(
        Prefetch('userrole_set', queryset=assigned, to_attr='bnk_assignments'),
    )


def member_response(member, actor):
    full_admin = any(assignment.role.name == FULL_ADMIN for assignment in member.bnk_assignments)
    user = member.user
    return {'id': str(member.pk), 'user_id': str(user.pk), 'name': user.get_full_name() or user.email,
            'email': user.email, 'role_ids': sorted({str(item.role_id) for item in member.bnk_assignments}),
            'locked': full_admin or member.user_id in {actor.user_id, actor.organization.owner_id} or not user.is_active}


def ensure_permissions(organization_id, codes):
    return [Permission.objects.get_or_create(organization_id=organization_id, name=code)[0] for code in codes]


def audit(actor, action, **metadata):
    AuditLog.objects.create(user=actor.user, action=f'bnk.iam.{action}', metadata={
        'organization_id': str(actor.organization_id), **metadata,
    })


class BnkView(APIView):
    authentication_classes = [BnkResourceAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def initial(self, request, *args, **kwargs):
        self.request_id = str(uuid4())
        super().initial(request, *args, **kwargs)
        self.actor = active_bnk_admin(request.user, UUID(request.auth['organization_id']))
        if (request.method not in {'GET', 'HEAD', 'OPTIONS', 'DELETE'}
                and not media_type_matches('application/json', request.content_type)):
            raise UnsupportedMediaType(request.content_type)

    @property
    def organization_id(self):
        return self.actor.organization_id

    def lock_actor(self):
        if lock_organization(self.organization_id) is None:
            raise PermissionDenied('Your active organization has changed. Refresh and try again.')
        self.actor = active_bnk_admin(self.request.user, self.organization_id, lock=True)

    def failure(self, code, detail, status):
        return Response({'error': code, 'detail': detail, 'request_id': self.request_id}, status=status)

    def handle_exception(self, exc):
        response = super().handle_exception(exc)
        data = response.data
        code = {400: 'invalid_input', 401: 'authentication_required', 403: 'permission_denied',
                404: 'not_found', 405: 'method_not_allowed', 415: 'unsupported_media_type',
                429: 'rate_limited'}.get(response.status_code, 'request_failed')
        detail = data.get('detail') if isinstance(data, dict) else None
        response.data = {'error': code, 'detail': str(detail) if detail else 'Review the submitted fields.',
                         'request_id': self.request_id}
        if response.status_code == 400 and not detail:
            response.data['fields'] = data
        return response

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response['Cache-Control'] = 'private, no-store'
        response['X-Request-ID'] = self.request_id
        return response


class BnkContextView(BnkView):
    def get(self, request):
        return Response({'subject': str(request.user.pk), 'organization_id': str(self.organization_id),
                         'can_manage': True, 'is_owner': request.user.pk == self.actor.organization.owner_id})


class BnkPermissionsView(BnkView):
    def get(self, request):
        return Response({'results': [{'code': code, 'module': module} for code, module in CATALOG.items()]})


class BnkRolesView(BnkView):
    def get(self, request):
        roles = present_roles(visible_roles(self.organization_id), self.organization_id).order_by('name', 'id')
        return Response({'results': [role_response(role) for role in roles]})

    @swagger_auto_schema(request_body=RoleInput, responses={201: 'BNK role created.'})
    @transaction.atomic
    def post(self, request):
        incoming = RoleInput(data=request.data)
        incoming.is_valid(raise_exception=True)
        self.lock_actor()
        values = incoming.validated_data
        if Role.objects.filter(organization_id=self.organization_id, name__iexact=values['name']).exists():
            return self.failure('role_name_conflict', 'A role with this name already exists.', 409)
        if managed_roles(self.organization_id).count() >= ROLE_LIMIT:
            return self.failure('role_limit_reached', 'The organization reached its BNK role limit.', 409)
        role = Role.objects.create(organization_id=self.organization_id, name=values['name'], description=values['description'])
        ProductManagedRole.objects.create(organization_id=self.organization_id, product_key=PRODUCT_KEY,
                                          managed_key=f'role-{role.pk}', role=role)
        role.permissions.set(ensure_permissions(self.organization_id, values['permission_codes']))
        audit(self.actor, 'role_created', role_id=str(role.pk), permission_codes=values['permission_codes'])
        return Response(role_response(present_roles(Role.objects.filter(pk=role.pk), self.organization_id).get()), status=201)


class BnkRoleDetailView(BnkView):
    def find_role(self, role_id):
        return managed_roles(self.organization_id).filter(pk=canonical_id(role_id)).first()

    @swagger_auto_schema(request_body=RoleInput(partial=True), responses={200: 'BNK role updated.'})
    @transaction.atomic
    def patch(self, request, role_id):
        incoming = RoleInput(data=request.data, partial=True)
        incoming.is_valid(raise_exception=True)
        self.lock_actor()
        role = self.find_role(role_id)
        if role is None:
            return self.failure('not_found', 'BNK role not found.', 404)
        values = incoming.validated_data
        if 'name' in values and Role.objects.filter(organization_id=self.organization_id, name__iexact=values['name']).exclude(pk=role.pk).exists():
            return self.failure('role_name_conflict', 'A role with this name already exists.', 409)
        if role.permissions.exclude(organization_id=self.organization_id, name__in=CATALOG).exists():
            return self.failure('role_outside_catalog', 'This role has unsupported permissions. Contact the organization owner.', 409)
        old_codes = sorted(role.permissions.values_list('name', flat=True))
        codes = values.get('permission_codes', old_codes)
        fields = [field for field in ('name', 'description') if field in values and getattr(role, field) != values[field]]
        for field in fields:
            setattr(role, field, values[field])
        if fields:
            role.save(update_fields=fields)
        if codes != old_codes:
            role.permissions.set(ensure_permissions(self.organization_id, codes))
        if fields or codes != old_codes:
            audit(self.actor, 'role_updated', role_id=str(role.pk), changed_fields=fields,
                  previous_permission_codes=old_codes, permission_codes=codes)
        return Response(role_response(present_roles(Role.objects.filter(pk=role.pk), self.organization_id).get()))

    @transaction.atomic
    def delete(self, request, role_id):
        self.lock_actor()
        role = self.find_role(role_id)
        if role is None:
            return self.failure('not_found', 'BNK role not found.', 404)
        if UserRole.objects.filter(role=role).exists() or DeviceRole.objects.filter(role=role).exists():
            return self.failure('role_in_use', 'Remove existing role assignments before deleting this role.', 409)
        audit(self.actor, 'role_deleted', role_id=str(role.pk))
        role.delete()
        return Response(status=204)


class BnkMembersView(BnkView):
    def get(self, request):
        requested_page = request.query_params.getlist('page') or ['1']
        if set(request.query_params) - {'page'} or len(requested_page) != 1 or not re.fullmatch(r'[1-9][0-9]{0,5}', requested_page[0]):
            return self.failure('invalid_input', 'Supply a valid page number.', 400)
        scoped = OrganizationMember.objects.filter(organization_id=self.organization_id)
        paginator = Paginator(records_for_members(scoped, self.organization_id).order_by('user__email', 'id'), 50)
        try:
            page = paginator.page(int(requested_page[0]))
        except EmptyPage:
            return self.failure('not_found', 'Member page not found.', 404)
        return Response({'count': paginator.count, 'next': page.next_page_number() if page.has_next() else None,
                         'previous': page.previous_page_number() if page.has_previous() else None,
                         'results': [member_response(member, self.actor) for member in page]})


class BnkMemberRolesView(BnkView):
    @swagger_auto_schema(request_body=AssignmentInput, responses={200: 'Member BNK assignments replaced.'})
    @transaction.atomic
    def put(self, request, member_id):
        incoming = AssignmentInput(data=request.data)
        incoming.is_valid(raise_exception=True)
        self.lock_actor()
        scoped = OrganizationMember.objects.filter(organization_id=self.organization_id, pk=canonical_id(member_id))
        member = scoped.select_related('user').select_for_update().first()
        if member is None:
            return self.failure('not_found', 'Organization member not found.', 404)
        if (member.user_id in {self.actor.user_id, self.actor.organization.owner_id} or not member.user.is_active
                or admin_assignments(self.organization_id).filter(organization_member=member).exists()):
            return self.failure('member_locked', 'This member’s BNK roles cannot be changed here.', 403)
        requested = set(incoming.validated_data['role_ids'])
        roles = managed_roles(self.organization_id)
        if roles.filter(pk__in=requested).count() != len(requested):
            return self.failure('not_found', 'One or more assignable BNK roles were not found.', 404)
        if Permission.objects.filter(roles__in=requested).exclude(organization_id=self.organization_id, name__in=CATALOG).exists():
            return self.failure('role_outside_catalog', 'A requested role has unsupported permissions.', 409)
        assigned = UserRole.objects.filter(organization_member=member, role__in=roles)
        current = set(assigned.values_list('role_id', flat=True))
        if current != requested:
            assigned.filter(role_id__in=current - requested).delete()
            UserRole.objects.bulk_create([UserRole(organization_member=member, role_id=pk) for pk in requested - current])
            audit(self.actor, 'member_roles_replaced', member_id=str(member.pk),
                  previous_role_ids=sorted(map(str, current)), role_ids=sorted(map(str, requested)))
        return Response(member_response(records_for_members(scoped, self.organization_id).get(), self.actor))
