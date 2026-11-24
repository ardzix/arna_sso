from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import skipUnless
from uuid import uuid4

import jwt
from django.conf import settings
from django.core.cache import cache
from django.db import close_old_connections, connection
from rest_framework.test import APIClient, APITestCase, APITransactionTestCase

from audit_logging.models import AuditLog
from authentication.models import User
from authentication.serializers import MyTokenObtainPairSerializer
from authentication.tests import test_device_iam
from iam.bnk_access import APP_CLIENT, AUDIENCE, FULL_ADMIN, PRODUCT_KEY
from iam.bnk_iam import CATALOG
from iam.models import Permission, Role, UserPermission, UserRole
from organization.models import Organization, OrganizationMember


BASE = '/api/v1/bnk/iam/'
EXCHANGE = '/api/v1/devices/resource-token/'


class BnkIamTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.owner, self.admin, self.member, self.outsider, self.disabled = [
            User.objects.create_user(email=f'{name}@bnk.example.test', password='synthetic', is_active=name != 'disabled')
            for name in ('owner', 'admin', 'member', 'outsider', 'disabled')
        ]
        self.org = Organization.objects.create(name='Synthetic BNK', owner=self.owner, package_type='Basic')
        self.other = Organization.objects.create(name='Other tenant organization', owner=self.outsider, package_type='Basic')
        self.members = {user.pk: OrganizationMember.objects.create(user=user, organization=self.org)
                        for user in (self.owner, self.admin, self.member, self.disabled)}
        self.foreign_member = OrganizationMember.objects.create(user=self.outsider, organization=self.other)
        self.system = Role.objects.create(organization=self.org, name=FULL_ADMIN, description='Existing delegation')
        self.full_grant = UserRole.objects.create(organization_member=self.members[self.admin.pk], role=self.system)
        self.external = Role.objects.create(organization=self.org, name='External operator')
        self.external_assignment = UserRole.objects.create(organization_member=self.members[self.member.pk], role=self.external)
        self.platform = Permission.objects.create(organization=self.org, name='organization.manage_roles')
        self.system.permissions.add(self.platform)
        self.direct = UserPermission.objects.create(organization_member=self.members[self.member.pk])
        self.direct.permissions.add(self.platform)

    @staticmethod
    def base_token(user, **overrides):
        access = MyTokenObtainPairSerializer.access_for_user(user)
        for key, value in {'app_client_id': APP_CLIENT, 'iss': settings.DEVICE_TOKEN_ISSUER, **overrides}.items():
            access[key] = value
        return str(access)

    def exchange(self, user=None, raw=None):
        raw = raw or self.base_token(user)
        return self.client.post(EXCHANGE, {'audience': AUDIENCE}, format='json', HTTP_AUTHORIZATION='Bearer ' + raw)

    def resource(self, user):
        response = self.exchange(user)
        self.assertEqual(response.status_code, 200, response.data)
        return response.data['access_token']

    def api(self, method, path, data=None, *, raw=None, **headers):
        if raw is not None:
            headers['HTTP_AUTHORIZATION'] = 'Bearer ' + raw
        return getattr(self.client, method)(BASE + path, data=data, format='json', **headers)

    def create_role(self, raw, name='Sales operator', codes=None):
        response = self.api('post', 'roles/', {'name': name, 'permission_codes': codes or ['crm.read']}, raw=raw)
        self.assertEqual(response.status_code, 201, response.data)
        return response.data['id']

    def decode(self, raw):
        return jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'],
                          issuer=settings.DEVICE_TOKEN_ISSUER, audience=AUDIENCE)

    def signed(self, claims, **overrides):
        return jwt.encode({**claims, **overrides}, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256')

    def test_only_owner_and_actual_assigned_full_admin_receive_management_tokens(self):
        for user, is_owner in [(self.owner, True), (self.admin, False)]:
            ordinary = self.base_token(user)
            response = self.exchange(raw=ordinary)
            self.assertEqual(response.status_code, 200)
            token = response.data['access_token']
            claims = self.decode(token)
            original = jwt.decode(ordinary, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'])
            self.assertLessEqual(claims['exp'], original['exp'])
            self.assertEqual(claims['token_type'], 'resource_access')
            self.assertEqual(claims['principal_type'], 'user')
            self.assertEqual(claims['organization_id'], str(self.org.pk))
            self.assertNotIn('tenant_id', claims)
            self.assertEqual(self.exchange(raw=token).status_code, 401)
            context = self.api('get', 'context/', raw=token)
            self.assertEqual(context.data, {'subject': str(user.pk), 'organization_id': str(self.org.pk),
                                            'can_manage': True, 'is_owner': is_owner})
            self.assertEqual(context['Cache-Control'], 'private, no-store')
        self.assertEqual(self.exchange(raw=self.base_token(self.member, roles=[FULL_ADMIN], is_owner=True)).status_code, 403)
        for overrides in ({'aud': 'arna-crm'}, {'app_client_id': 'arna-account'}, {'iss': 'https://other.example.test'}):
            self.assertEqual(self.exchange(raw=self.base_token(self.owner, **overrides)).status_code, 403)
        self.member.is_staff = True
        self.member.is_superuser = True
        self.member.save(update_fields=['is_staff', 'is_superuser'])
        self.assertEqual(self.exchange(self.member).status_code, 403)

    def test_resource_auth_is_strict_and_database_authority_is_revalidated(self):
        token = self.resource(self.admin)
        self.assertEqual(self.api('get', 'context/').status_code, 401)
        self.assertEqual(self.api('get', 'context/', raw=self.base_token(self.admin)).status_code, 401)
        claims = self.decode(token)
        for overrides in ({'aud': 'arna-levelup'}, {'aud': [AUDIENCE]}, {'principal_type': 'service'},
                          {'principal_type': 'device'}, {'token_type': 'access'}, {'iss': 'https://other.example.test'},
                          {'app_client_id': 'arna-account'},
                          {'organization_id': str(self.other.pk)}, {'user_id': 'not-a-user'}, {'exp': claims['iat'] - 1}):
            with self.subTest(overrides=overrides):
                response = self.api('get', 'context/', raw=self.signed(claims, **overrides))
                self.assertEqual(response.status_code, 401, response.data)
                self.assertEqual(response.data['error'], 'authentication_required')
                self.assertTrue(response.data['request_id'])
        self.full_grant.delete()
        response = self.api('get', 'context/', raw=token, HTTP_X_ARNA_ROLE=FULL_ADMIN,
                            HTTP_X_BNK_ORGANIZATION_ID=str(self.org.pk))
        self.assertEqual(response.status_code, 403)

    def test_active_organization_is_derived_from_signed_context_and_database(self):
        token = self.resource(self.owner)
        OrganizationMember.objects.filter(pk=self.members[self.owner.pk].pk).update(is_session_active=False)
        OrganizationMember.objects.create(user=self.owner, organization=self.other)
        response = self.api('get', 'members/', raw=token, HTTP_X_ARNA_ORGANIZATION_ID=str(self.other.pk))
        self.assertEqual(response.status_code, 403)
        response = self.exchange(raw=self.base_token(self.owner, org_id=str(self.org.pk)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.exchange(self.owner).status_code, 403)

    def test_catalog_is_read_only_allowlisted_and_role_crud_is_audited(self):
        raw = self.resource(self.admin)
        catalog = self.api('get', 'permissions/', raw=raw).data['results']
        self.assertEqual({item['code']: item['module'] for item in catalog}, CATALOG)
        self.assertNotIn(self.platform.name, {item['code'] for item in catalog})
        self.assertEqual(self.api('post', 'permissions/', {}, raw=raw).status_code, 405)
        self.assertEqual(self.api('post', 'roles/', {'name': 'Bad', 'permission_codes': [self.platform.name]}, raw=raw).status_code, 400)
        self.assertEqual(self.api('post', 'roles/', {'name': ' FULL   ADMIN ', 'permission_codes': []}, raw=raw).status_code, 400)
        self.assertEqual(self.api('post', 'roles/', {'name': 'Bad', 'permission_codes': [], 'organization_id': str(self.other.pk)}, raw=raw).status_code, 400)
        role_id = self.create_role(raw, codes=['crm.read', 'crm.read', 'business_hub:read'])
        role = Role.objects.get(pk=role_id)
        self.assertEqual(role.product_management.product_key, PRODUCT_KEY)
        self.assertEqual(role.organization_id, self.org.pk)
        self.assertEqual(set(role.permissions.values_list('name', flat=True)), {'crm.read', 'business_hub:read'})
        self.assertEqual(self.api('post', 'roles/', {'name': 'sALES oPERATOR', 'permission_codes': []}, raw=raw).status_code, 409)
        change = self.api('patch', f'roles/{role_id}/', {'name': 'Inbox operator', 'permission_codes': ['crm.inbox.read']}, raw=raw)
        self.assertEqual(change.status_code, 200, change.data)
        self.assertEqual(change.data['permission_codes'], ['crm.inbox.read'])
        self.assertEqual(self.api('patch', f'roles/{role_id}/', {'name': 'Inbox operator'}, raw=raw).status_code, 200)
        self.assertEqual(self.api('delete', f'roles/{role_id}/', raw=raw).status_code, 204)
        evidence = AuditLog.objects.filter(action__startswith='bnk.iam.').order_by('created_at')
        self.assertEqual(list(evidence.values_list('action', flat=True)), ['bnk.iam.role_created', 'bnk.iam.role_updated', 'bnk.iam.role_deleted'])
        self.assertEqual(set(evidence.values_list('user_id', flat=True)), {self.admin.pk})
        self.assertEqual(evidence.first().metadata['organization_id'], str(self.org.pk))

    def test_locked_and_external_roles_and_foreign_ids_cannot_be_modified(self):
        raw = self.resource(self.admin)
        product_role = self.create_role(raw)
        listed = self.api('get', 'roles/', raw=raw).data['results']
        self.assertEqual({role['id'] for role in listed}, {str(self.system.pk), product_role})
        locked = next(role for role in listed if role['locked'])
        self.assertEqual(locked['name'], FULL_ADMIN)
        self.assertEqual(locked['permission_codes'], [])
        self.assertEqual(locked['member_count'], 1)
        foreign_id = self.create_role(self.resource(self.outsider), name='Foreign role')
        for target in (self.system.pk, self.external.pk, foreign_id, uuid4(), 'invalid'):
            for method in ('patch', 'delete'):
                data = {'name': 'Tampered'} if method == 'patch' else None
                self.assertEqual(self.api(method, f'roles/{target}/', data, raw=raw).status_code, 404)
        self.assertEqual(self.api('put', f'members/{self.foreign_member.pk}/roles/', {'role_ids': []}, raw=raw).status_code, 404)
        member_pk = self.members[self.member.pk].pk
        for target in (self.system.pk, self.external.pk, foreign_id, uuid4()):
            self.assertEqual(self.api('put', f'members/{member_pk}/roles/', {'role_ids': [str(target)]}, raw=raw).status_code, 404)
        for target in (self.owner, self.admin, self.disabled):
            self.assertEqual(self.api('put', f'members/{self.members[target.pk].pk}/roles/', {'role_ids': [product_role]}, raw=raw).status_code, 403)
        self.assertEqual(set(self.system.permissions.values_list('name', flat=True)), {self.platform.name})
        self.assertTrue(UserRole.objects.filter(pk=self.full_grant.pk).exists())

    def test_assignments_preserve_external_roles_and_direct_permissions_on_replay(self):
        raw = self.resource(self.owner)
        first = self.create_role(raw, name='Reader')
        second = self.create_role(raw, name='Writer', codes=['operations.write'])
        target = self.members[self.member.pk].pk
        for requested in ([first, first, second], [second, first]):
            response = self.api('put', f'members/{target}/roles/', {'role_ids': requested}, raw=raw)
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(set(response.data['role_ids']), {first, second})
            self.assertFalse(response.data['locked'])
        self.assertEqual(UserRole.objects.filter(organization_member_id=target, role_id=first).count(), 1)
        member_claims = jwt.decode(self.base_token(self.member), settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'])
        self.assertTrue({'crm.read', 'operations.write', self.platform.name}.issubset(member_claims['permissions']))
        logs = AuditLog.objects.filter(action='bnk.iam.member_roles_replaced')
        self.assertEqual(logs.count(), 1)
        self.assertEqual(self.api('delete', f'roles/{first}/', raw=raw).data['error'], 'role_in_use')
        response = self.api('put', f'members/{target}/roles/', {'role_ids': []}, raw=raw)
        self.assertEqual(response.data['role_ids'], [])
        self.assertEqual(logs.count(), 2)
        self.assertTrue(UserRole.objects.filter(pk=self.external_assignment.pk).exists())
        self.assertEqual(list(self.direct.permissions.values_list('pk', flat=True)), [self.platform.pk])
        self.assertEqual(self.api('delete', f'roles/{first}/', raw=raw).status_code, 204)

    def test_member_list_has_bounded_pagination_and_no_foreign_pii(self):
        raw = self.resource(self.owner)
        response = self.api('get', 'members/', raw=raw)
        self.assertEqual(response.data['count'], 4)
        self.assertIsNone(response.data['next'])
        listed = {row['id']: row for row in response.data['results']}
        self.assertNotIn(str(self.foreign_member.pk), listed)
        self.assertEqual(listed[str(self.members[self.admin.pk].pk)]['role_ids'], [str(self.system.pk)])
        self.assertTrue(listed[str(self.members[self.admin.pk].pk)]['locked'])
        for query in ('page=0', 'page=1&page=2', 'organization=' + str(self.other.pk)):
            self.assertEqual(self.api('get', 'members/?' + query, raw=raw).status_code, 400)
        self.assertEqual(self.api('get', 'members/?page=2', raw=raw).status_code, 404)

    def test_legacy_routes_cannot_mint_admin_or_bypass_bnk_role_boundaries(self):
        owner_raw, staff_raw = self.base_token(self.owner), self.base_token(self.member)
        raw = self.resource(self.owner)
        bnk_id = self.create_role(raw)
        permission_id = Role.objects.get(pk=bnk_id).permissions.get().pk
        staff_auth = {'HTTP_AUTHORIZATION': 'Bearer ' + staff_raw}
        owner_auth = {'HTTP_AUTHORIZATION': 'Bearer ' + owner_raw}
        self.assertEqual(self.client.post('/api/iam/roles/', {'name': ' full admin '}, format='json', **staff_auth).status_code, 403)
        for role in (self.external.pk, self.system.pk):
            response = self.client.patch(f'/api/iam/roles/{role}/', {'name': FULL_ADMIN}, format='json', **staff_auth)
            self.assertEqual(response.status_code, 403, response.data)
        self.assertEqual(self.client.delete(f'/api/iam/roles/{self.system.pk}/', **staff_auth).status_code, 403)
        self.assertEqual(self.client.patch(f'/api/iam/roles/{bnk_id}/', {'permission_ids': [str(self.platform.pk)]}, format='json', **owner_auth).status_code, 403)
        self.assertEqual(self.client.delete(f'/api/iam/roles/{bnk_id}/', **owner_auth).status_code, 403)
        self.assertEqual(self.client.patch(f'/api/iam/permissions/{permission_id}/', {'name': 'other.permission'}, format='json', **owner_auth).status_code, 403)
        target = self.members[self.member.pk].pk
        for role, headers in [(bnk_id, owner_auth), (self.system.pk, staff_auth)]:
            response = self.client.post('/api/iam/user-roles/', {'organization_member': str(target), 'role': str(role)}, format='json', **headers)
            self.assertEqual(response.status_code, 403, response.data)
        self.assertEqual(self.client.delete(f'/api/iam/user-roles/{self.full_grant.pk}/', **staff_auth).status_code, 403)
        self.assertEqual(self.client.patch(f'/api/iam/roles/{self.external.pk}/', {'name': 'External renamed'}, format='json', **owner_auth).status_code, 200)


class BnkIamDeviceTests(APITestCase):
    setUp = test_device_iam.DeviceIAMTests.setUp
    pair = test_device_iam.DeviceIAMTests.pair

    def test_registered_device_cannot_exchange_bnk_administration_token(self):
        token = self.pair()['access_token']
        self.client.force_authenticate(user=None)
        response = self.client.post(EXCHANGE, {'audience': AUDIENCE}, format='json',
                                    HTTP_AUTHORIZATION='Bearer ' + token)
        self.assertEqual(response.status_code, 403, response.data)


@skipUnless(connection.vendor == 'postgresql', 'PostgreSQL row-level locking test')
class BnkIamConcurrencyTests(APITransactionTestCase):
    base_token = staticmethod(BnkIamTests.base_token)
    exchange = BnkIamTests.exchange
    resource = BnkIamTests.resource
    api = BnkIamTests.api
    create_role = BnkIamTests.create_role

    def test_concurrent_identical_assignments_record_one_row_and_audit_event(self):
        cache.clear()
        owner = User.objects.create_user(email='parallel-owner@bnk.example.test', password='synthetic', is_active=True)
        user = User.objects.create_user(email='parallel-target@bnk.example.test', password='synthetic', is_active=True)
        organization = Organization.objects.create(owner=owner, name='Parallel BNK', package_type='Basic')
        OrganizationMember.objects.create(user=owner, organization=organization)
        target = OrganizationMember.objects.create(user=user, organization=organization)
        token = self.resource(owner)
        role_id = self.create_role(token)
        barrier = Barrier(2, timeout=8)

        def assign():
            try:
                barrier.wait()
                response = APIClient().put(f'{BASE}members/{target.pk}/roles/', {'role_ids': [role_id]},
                                           format='json', HTTP_AUTHORIZATION='Bearer ' + token)
                return response.status_code, response.data.get('role_ids')
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: assign(), range(2)))
        self.assertEqual(outcomes, [(200, [role_id]), (200, [role_id])])
        self.assertEqual(UserRole.objects.filter(organization_member=target, role_id=role_id).count(), 1)
        self.assertEqual(AuditLog.objects.filter(action='bnk.iam.member_roles_replaced').count(), 1)
