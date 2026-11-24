import uuid

import jwt
from django.conf import settings
from rest_framework.test import APITestCase

from authentication.serializers import MyTokenObtainPairSerializer
from authentication.tests.test_device_iam import DeviceIAMTests
from iam.effective import OPERATIONS_PERMISSIONS
from iam.models import Permission, UserRole


class HumanOperationsTests(APITestCase):
    setUp = DeviceIAMTests.setUp
    pair = DeviceIAMTests.pair

    def exchange(self, user, raw=None):
        self.client.force_authenticate(user=None)
        raw = raw or str(MyTokenObtainPairSerializer.get_token(user).access_token)
        return self.client.post('/api/v1/devices/resource-token/', {'audience': 'arna-operations'},
            format='json', HTTP_AUTHORIZATION='Bearer ' + raw)

    def claims(self, response):
        self.assertEqual(response.status_code, 200, response.data)
        return jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
            algorithms=['RS256'], issuer=settings.DEVICE_TOKEN_ISSUER, audience='arna-operations')

    def test_owner_token_is_tenant_bound_with_only_operations_permissions(self):
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        subject = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], options={'verify_aud': False})
        claims = self.claims(self.exchange(self.owner, raw))
        self.assertEqual(claims['tenant_id'], str(self.tenant))
        self.assertEqual(claims['organization_id'], str(self.org.pk))
        self.assertEqual(set(claims['permissions']), OPERATIONS_PERMISSIONS)
        self.assertEqual(claims['principal_type'], 'user')
        self.assertLessEqual(claims['exp'], subject['exp'])
        self.assertFalse(claims['is_staff'])
        self.assertFalse(claims['is_superuser'])

    def test_member_needs_explicit_grant_and_revocation_is_immediate(self):
        self.assertEqual(self.exchange(self.staff).status_code, 403)
        grant = Permission.objects.get(organization=self.org, name='operations.read')
        self.role.permissions.add(grant)
        UserRole.objects.create(organization_member=self.staff_member, role=self.role)
        raw = str(MyTokenObtainPairSerializer.get_token(self.staff).access_token)
        self.assertEqual(self.claims(self.exchange(self.staff, raw))['permissions'], ['operations.read'])
        self.role.permissions.remove(grant)
        self.assertEqual(self.exchange(self.staff, raw).status_code, 403)

    def test_no_missing_revoked_ambiguous_or_failed_workspace_can_issue_token(self):
        self.lookup.return_value.json.return_value = {'results': []}
        self.assertEqual(self.exchange(self.owner).status_code, 400)
        self.lookup.return_value.json.return_value = {'results': [
            {'tenant_id': str(value), 'sso_organization_id': str(self.org.pk), 'is_active': True}
            for value in (self.tenant, uuid.uuid4())]}
        self.assertEqual(self.exchange(self.owner).status_code, 400)
        self.member.active_tenant_id = self.tenant
        self.member.save(update_fields=['active_tenant_id'])
        self.lookup.return_value.json.return_value = {'results': []}
        self.assertEqual(self.exchange(self.owner).status_code, 403)
        self.lookup.return_value.status_code = 503
        self.assertEqual(self.exchange(self.owner).status_code, 503)

    def test_foreign_or_stale_subject_scope_is_denied(self):
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        subject = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], options={'verify_aud': False})
        subject['org_id'] = str(uuid.uuid4())
        self.assertEqual(self.exchange(self.owner, jwt.encode(subject, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256')).status_code, 403)
        subject['org_id'] = str(self.org.pk)
        subject['tenant_id'] = str(uuid.uuid4())
        self.assertEqual(self.exchange(self.owner, jwt.encode(subject, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256')).status_code, 403)

    def test_device_cannot_exchange_for_human_operations(self):
        pair = self.pair()
        response = self.exchange(self.owner, pair['access_token'])
        self.assertEqual(response.status_code, 403)

    def test_catalog_entries_do_not_assign_permissions_to_member(self):
        self.assertEqual(Permission.objects.filter(organization=self.org, name__in=OPERATIONS_PERMISSIONS).count(), 3)
        self.assertFalse(UserRole.objects.filter(organization_member=self.staff_member).exists())
        self.assertEqual(self.exchange(self.staff).status_code, 403)
