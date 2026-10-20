import base64
import hashlib
import time
import uuid
from unittest.mock import Mock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.core.cache import cache
from rest_framework.test import APITestCase

from authentication.models import User, DeviceRegistration, DeviceRefreshCredential
from authentication.serializers import MyTokenObtainPairSerializer
from iam.models import Permission, Role, UserRole, DeviceRole
from organization.models import Organization, OrganizationMember

BASE = '/api/v1/devices/'


class DeviceIAMTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.owner = User.objects.create_user(email='iam-device-owner@example.test', password='synthetic', is_active=True)
        self.staff = User.objects.create_user(email='iam-device-staff@example.test', password='synthetic', is_active=True)
        self.org = Organization.objects.create(owner=self.owner, name='Device IAM', package_type='Basic')
        self.tenant = uuid.uuid4()
        self.member = OrganizationMember.objects.create(user=self.owner, organization=self.org)
        self.staff_member = OrganizationMember.objects.create(user=self.staff, organization=self.org)
        self.read = Permission.objects.get(organization=self.org, name='storage.files.read')
        self.create = Permission.objects.get(organization=self.org, name='storage.files.create')
        self.role = Role.objects.create(organization=self.org, name='File operator')
        self.role.permissions.add(self.read, self.create)
        self.lookup = patch('authentication.device_security.requests.get', return_value=Mock(status_code=200,
            json=Mock(return_value={'results': [{'tenant_id': str(self.tenant), 'sso_organization_id': str(self.org.pk), 'is_active': True}]}))).start()
        self.addCleanup(patch.stopall)

    def pair(self, **extra):
        self.client.force_authenticate(user=None)
        grant = self.client.post(BASE + 'authorize/', {'client_id': 'iam-device', 'device_name': 'Tenant kiosk',
            'audience': 'photobooth-api', 'scopes': ['photobooth.session'], **extra}, format='json')
        self.assertEqual(grant.status_code, 201, grant.data)
        self.client.force_authenticate(user=self.owner)
        approved = self.client.post(BASE + 'verification/', {'user_code': grant.data['user_code'], 'action': 'approve'}, format='json')
        self.assertEqual(approved.status_code, 200, approved.data)
        pair = self.client.post(BASE + 'token/', {'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': grant.data['device_code']}, format='json')
        self.assertEqual(pair.status_code, 200, pair.data)
        return pair.data

    def assign(self, pair, **extra):
        self.client.force_authenticate(user=self.owner)
        return self.client.put(BASE + f"registrations/{pair['device_id']}/access/", {
            'role_ids': [str(self.role.pk)], 'permission_ids': [], **extra}, format='json')

    def resource(self, raw, **headers):
        self.client.force_authenticate(user=None)
        return self.client.post(BASE + 'resource-token/', {'audience': 'storage'}, format='json',
            HTTP_AUTHORIZATION='Bearer ' + raw, **headers)

    def test_pairing_derives_org_and_tenant_without_device_supplied_ids(self):
        pair = self.pair()
        self.assertEqual(pair['organization_id'], str(self.org.pk))
        self.assertEqual(pair['tenant_id'], str(self.tenant))
        self.member.refresh_from_db()
        self.assertEqual(self.member.active_tenant_id, self.tenant)

    def test_human_org_storage_without_arnasite_tenant_preserves_grants_and_expiry(self):
        self.lookup.return_value.json.return_value = {'results': []}
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        response = self.resource(raw)
        self.assertEqual(response.status_code, 200, response.data)
        claims = jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
                            algorithms=['RS256'], audience='storage', issuer=settings.DEVICE_TOKEN_ISSUER)
        self.assertEqual(claims['org_id'], str(self.org.pk))
        self.assertEqual(claims['user_id'], str(self.owner.pk))
        self.assertIsNone(claims['tenant_id'])
        self.assertEqual(claims['principal_type'], 'user')
        self.assertIn('storage.files.create', claims['permissions'])
        self.assertIn('storage.files.share', claims['permissions'])
        subject = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], options={'verify_aud': False})
        self.assertLessEqual(claims['exp'], subject['exp'])
        staff_token = str(MyTokenObtainPairSerializer.get_token(self.staff).access_token)
        self.assertEqual(self.resource(staff_token).status_code, 403)
        UserRole.objects.create(organization_member=self.staff_member, role=self.role)
        response = self.resource(staff_token)
        self.assertEqual(response.status_code, 200, response.data)
        claims = jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], audience='storage')
        self.assertEqual(claims['permissions'], ['storage.files.create', 'storage.files.read'])
        self.assertIsNone(claims['tenant_id'])
        self.assertFalse(claims['is_owner'])

    def test_human_org_storage_never_downgrades_ambiguous_revoked_or_unavailable_tenant(self):
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        rows = self.lookup.return_value.json.return_value['results']
        rows.append({**rows[0], 'tenant_id': str(uuid.uuid4())})
        self.assertEqual(self.resource(raw).status_code, 400)
        self.member.active_tenant_id = self.tenant
        self.member.save(update_fields=['active_tenant_id'])
        self.lookup.return_value.json.return_value = {'results': []}
        self.assertEqual(self.resource(raw).status_code, 403)
        self.member.active_tenant_id = None
        self.member.save(update_fields=['active_tenant_id'])
        self.lookup.return_value.status_code = 503
        self.assertEqual(self.resource(raw).status_code, 503)

    def test_human_resource_rejects_stale_signed_org_and_workspace(self):
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        claims = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], options={'verify_aud': False})
        claims['org_id'] = str(uuid.uuid4())
        self.assertEqual(self.resource(jwt.encode(claims, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256')).status_code, 403)
        claims['org_id'] = str(self.org.pk)
        claims['tenant_id'] = str(uuid.uuid4())
        self.assertEqual(self.resource(jwt.encode(claims, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256')).status_code, 403)

    def test_device_pairing_still_requires_tenant_for_org_without_workspaces(self):
        self.lookup.return_value.json.return_value = {'results': []}
        self.client.force_authenticate(user=None)
        grant = self.client.post(BASE + 'authorize/', {'client_id': 'no-workspace', 'device_name': 'Kiosk',
            'audience': 'photobooth-api', 'scopes': ['photobooth.session']}, format='json')
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(BASE + 'verification/', {'user_code': grant.data['user_code'], 'action': 'approve'}, format='json')
        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(DeviceRegistration.objects.exists())

    def test_shared_role_catalogue_and_resource_permissions_for_human_and_device(self):
        pair = self.pair()
        self.assertEqual(self.resource(pair['access_token']).status_code, 403)
        self.assertEqual(self.assign(pair).status_code, 200)
        response = self.resource(pair['access_token'])
        self.assertEqual(response.status_code, 200, response.data)
        device_claims = jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'],
                                  audience='storage', issuer=settings.DEVICE_TOKEN_ISSUER)
        self.assertEqual(device_claims['permissions'], ['storage.files.create', 'storage.files.read'])
        self.assertFalse(device_claims['is_owner'])
        self.assertEqual(device_claims['device_id'], pair['device_id'])
        self.assertEqual(DeviceRefreshCredential.objects.count(), 1)
        UserRole.objects.create(organization_member=self.staff_member, role=self.role)
        human = str(MyTokenObtainPairSerializer.get_token(self.staff).access_token)
        result = self.resource(human)
        self.assertEqual(result.status_code, 200, result.data)
        human_claims = jwt.decode(result.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], audience='storage', issuer=settings.DEVICE_TOKEN_ISSUER)
        self.assertEqual(human_claims['permissions'], device_claims['permissions'])
        self.assertEqual(human_claims['tenant_id'], str(self.tenant))
        self.assertEqual(human_claims['principal_type'], 'user')

    def test_permission_removal_invalidates_storage_token_but_preserves_pairing(self):
        from authentication.device_security import device_token_registration
        from rest_framework.exceptions import AuthenticationFailed
        pair = self.pair()
        self.assign(pair)
        resource = self.resource(pair['access_token']).data['access_token']
        self.assertEqual(device_token_registration(resource, 'storage')[0].pk, uuid.UUID(pair['device_id']))
        self.role.permissions.remove(self.read)
        with self.assertRaises(AuthenticationFailed):
            device_token_registration(resource, 'storage')
        self.assertEqual(device_token_registration(pair['access_token'], 'photobooth-api')[0].pk, uuid.UUID(pair['device_id']))
        fresh = self.resource(pair['access_token'])
        self.assertEqual(fresh.status_code, 200)

    def test_resource_token_cannot_extend_subject_expiry(self):
        pair = self.pair()
        self.assign(pair)
        from authentication.device_views import _device_access_token
        expiration = int(time.time()) + 45
        device = DeviceRegistration.objects.get(pk=pair['device_id'])
        response = self.resource(_device_access_token(device, subject_exp=expiration))
        self.assertEqual(response.status_code, 200, response.data)
        claims = jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
                            algorithms=['RS256'], audience='storage', issuer=settings.DEVICE_TOKEN_ISSUER)
        self.assertEqual(claims['exp'], expiration)
        self.assertLessEqual(response.data['expires_in'], 45)
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        human_claims = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], options={'verify_aud': False})
        human_claims['exp'] = expiration
        raw = jwt.encode(human_claims, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256')
        response = self.resource(raw)
        self.assertEqual(response.status_code, 200, response.data)
        claims = jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
                            algorithms=['RS256'], audience='storage', issuer=settings.DEVICE_TOKEN_ISSUER)
        self.assertEqual(claims['exp'], expiration)
        response = self.resource(response.data['access_token'])
        self.assertEqual(response.status_code, 200, response.data)
        claims = jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
                            algorithms=['RS256'], audience='storage', issuer=settings.DEVICE_TOKEN_ISSUER)
        self.assertEqual(claims['exp'], expiration)

    def test_storage_introspection_matches_file_manager_contract_and_revokes_immediately(self):
        from authentication.models import ServiceAccount
        pair = self.pair()
        self.assign(pair)
        resource = self.resource(pair['access_token']).data['access_token']
        service = ServiceAccount(name='Storage inspector', client_id='storage-inspector',
                                 scopes=['sso.device.introspect'], audiences=['arna-sso-devices'])
        service.set_client_secret('synthetic-only')
        service.save()
        auth = self.client.post('/api/auth/service-token/', {'client_id': service.client_id,
            'client_secret': 'synthetic-only', 'audience': 'arna-sso-devices'}, format='json')
        self.assertEqual(auth.status_code, 200, auth.data)
        headers = {'HTTP_AUTHORIZATION': 'Bearer ' + auth.data['access']}
        payload = {'access_token': resource, 'audience': 'storage'}
        response = self.client.post(BASE + 'introspect/', payload, format='json', **headers)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data['active'])
        claims = jwt.decode(resource, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], audience='storage')
        for name in ('device_id', 'tenant_id', 'credential_version', 'permissions', 'scopes'):
            self.assertEqual(response.data[name], claims[name])
        self.assertEqual(response.data['audience'], 'storage')
        self.assertEqual(response.data['organization_id'], str(self.org.pk))
        self.role.permissions.remove(self.read)
        response = self.client.post(BASE + 'introspect/', payload, format='json', **headers)
        self.assertEqual(response.data, {'active': False})

    def test_foreign_roles_and_malformed_ids_are_400_and_atomic(self):
        pair = self.pair()
        other_org = Organization.objects.create(owner=self.staff, name='Foreign', package_type='Basic')
        foreign = Role.objects.create(organization=other_org, name='Foreign')
        for value in ('not-uuid', str(foreign.pk)):
            response = self.assign(pair, role_ids=[value])
            self.assertEqual(response.status_code, 400, response.data)
            self.assertIn('request_id', response.data)
            self.assertFalse(DeviceRole.objects.exists())

    def test_superuser_without_tenant_authority_cannot_pair(self):
        grant = self.client.post(BASE + 'authorize/', {'client_id': 'foreign', 'device_name': 'Unapproved',
            'audience': 'photobooth-api', 'scopes': ['photobooth.session']}, format='json')
        self.staff.is_superuser = True
        self.staff.save()
        self.client.force_authenticate(user=self.staff)
        response = self.client.post(BASE + 'verification/', {'user_code': grant.data['user_code'], 'action': 'approve'}, format='json')
        self.assertEqual(response.status_code, 403)
        self.lookup.assert_not_called()
        self.assertFalse(DeviceRegistration.objects.exists())

    def test_multiple_workspaces_require_verified_selection_and_legacy_hint_matches(self):
        second = uuid.uuid4()
        self.lookup.return_value.json.return_value['results'].append({'tenant_id': str(second),
            'sso_organization_id': str(self.org.pk), 'is_active': True})
        self.client.force_authenticate(user=self.owner)
        context = self.client.get(BASE + 'context/')
        self.assertIsNone(context.data['tenant_id'])
        self.assertEqual(self.client.post(BASE + 'context/', {'tenant_id': str(uuid.uuid4())}, format='json').status_code, 403)
        self.assertEqual(self.client.post(BASE + 'context/', {'tenant_id': str(second)}, format='json').status_code, 200)
        pair = self.pair(tenant_id=str(second))
        self.assertEqual(pair['tenant_id'], str(second))
        self.client.force_authenticate(user=self.owner)
        self.client.post(BASE + 'context/', {'tenant_id': str(self.tenant)}, format='json')
        self.assertEqual(self.client.get(BASE + f"registrations/{pair['device_id']}/").status_code, 404)
        self.assertEqual(self.assign(pair).status_code, 404)

    def test_device_admin_cannot_delegate_permissions_they_do_not_hold(self):
        pair = self.pair()
        admin_role = Role.objects.create(organization=self.org, name='Device admin')
        for name in ('device.activate', 'organization.manage_roles'):
            permission = Permission.objects.create(organization=self.org, name=name)
            admin_role.permissions.add(permission)
        UserRole.objects.create(organization_member=self.staff_member, role=admin_role)
        self.client.force_authenticate(user=self.staff)
        response = self.client.put(BASE + f"registrations/{pair['device_id']}/access/", {
            'role_ids': [str(self.role.pk)], 'permission_ids': []}, format='json')
        self.assertEqual(response.status_code, 403)
        admin_role.permissions.add(self.read, self.create)
        response = self.client.put(BASE + f"registrations/{pair['device_id']}/access/", {
            'role_ids': [str(self.role.pk)], 'permission_ids': []}, format='json')
        self.assertEqual(response.status_code, 200, response.data)

    def test_resource_token_preserves_dpop_binding_and_rejects_replay(self):
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        public = {'kty': 'EC', 'crv': 'P-256',
                  'x': base64.urlsafe_b64encode(numbers.x.to_bytes(32, 'big')).rstrip(b'=').decode(),
                  'y': base64.urlsafe_b64encode(numbers.y.to_bytes(32, 'big')).rstrip(b'=').decode()}
        canonical = {name: public[name] for name in ('crv', 'kty', 'x', 'y')}
        import json
        thumb = base64.urlsafe_b64encode(hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()).digest()).rstrip(b'=').decode()
        pair = self.pair()
        self.assign(pair)
        device = DeviceRegistration.objects.get(pk=pair['device_id'])
        device.public_key_thumbprint = thumb
        device.save()
        from authentication.device_views import _device_access_token
        raw = _device_access_token(device)
        proof = jwt.encode({'iat': int(time.time()), 'jti': str(uuid.uuid4()), 'htm': 'POST',
            'htu': settings.DEVICE_PUBLIC_ORIGIN + BASE + 'resource-token/',
            'ath': base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()).rstrip(b'=').decode()}, key,
            algorithm='ES256', headers={'typ': 'dpop+jwt', 'jwk': public})
        self.client.force_authenticate(user=None)
        headers = {'HTTP_AUTHORIZATION': 'DPoP ' + raw, 'HTTP_DPOP': proof}
        response = self.client.post(BASE + 'resource-token/', {'audience': 'storage'}, format='json', **headers)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['token_type'], 'DPoP')
        self.assertEqual(self.client.post(BASE + 'resource-token/', {'audience': 'storage'}, format='json', **headers).status_code, 400)
