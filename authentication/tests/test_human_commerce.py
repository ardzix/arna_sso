import uuid
from unittest.mock import patch
import jwt
from django.conf import settings
from rest_framework.test import APITestCase
from authentication.tests.test_device_iam import DeviceIAMTests
from authentication.serializers import MyTokenObtainPairSerializer
from iam.models import Permission, UserRole


class HumanCommerceTests(APITestCase):
    setUp = DeviceIAMTests.setUp

    def exchange(self, user, raw=None):
        self.client.force_authenticate(user=None)
        raw = raw or str(MyTokenObtainPairSerializer.get_token(user).access_token)
        return self.client.post('/api/v1/devices/resource-token/', {'audience': 'arna-commerce'},
            format='json', HTTP_AUTHORIZATION='Bearer '+raw)

    def claims(self, response):
        self.assertEqual(response.status_code, 200, response.data)
        return jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'],
                          issuer=settings.DEVICE_TOKEN_ISSUER, audience='arna-commerce')

    def test_owner_gets_tenant_catalog_grants_without_platform_flags(self):
        claims = self.claims(self.exchange(self.owner))
        self.assertEqual(claims['tenant_id'], str(self.tenant))
        self.assertEqual(claims['org_id'], str(self.org.pk))
        self.assertEqual(claims['principal_type'], 'user')
        self.assertEqual(claims['email'], self.owner.email)
        self.assertIn('commerce.catalog.write', claims['permissions'])
        self.assertIn('commerce.catalog.delete', claims['permissions'])
        self.assertNotIn('storage.files.create', claims['permissions'])
        self.assertNotIn('commerce.payments.process', claims['permissions'])
        self.assertFalse(claims['is_staff'])
        self.assertFalse(claims['is_superuser'])

    def test_staff_grants_are_filtered_and_revoked_on_next_exchange(self):
        self.assertEqual(self.exchange(self.staff).status_code, 403)
        grant = Permission.objects.get(organization=self.org, name='commerce.catalog.write')
        self.role.permissions.add(grant)
        UserRole.objects.create(organization_member=self.staff_member, role=self.role)
        raw = str(MyTokenObtainPairSerializer.get_token(self.staff).access_token)
        claims = self.claims(self.exchange(self.staff, raw))
        self.assertEqual(claims['permissions'], ['commerce.catalog.write'])
        self.role.permissions.remove(grant)
        self.assertEqual(self.exchange(self.staff, raw).status_code, 403)

    def test_workspace_selection_revocation_and_lookup_failure_never_issue_unbound_commerce_tokens(self):
        self.lookup.return_value.json.return_value = {'results': []}
        self.assertEqual(self.exchange(self.owner).status_code, 400)
        self.lookup.return_value.json.return_value = {'results': [
            {'tenant_id': str(x), 'sso_organization_id': str(self.org.pk), 'is_active': True}
            for x in (self.tenant, uuid.uuid4())]}
        self.assertEqual(self.exchange(self.owner).status_code, 400)
        self.member.active_tenant_id = self.tenant
        self.member.save(update_fields=['active_tenant_id'])
        self.lookup.return_value.json.return_value = {'results': []}
        self.assertEqual(self.exchange(self.owner).status_code, 403)
        self.lookup.return_value.status_code = 503
        self.assertEqual(self.exchange(self.owner).status_code, 503)

    def test_subject_context_and_expiry_are_preserved(self):
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        subject = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'], options={'verify_aud': False})
        claims = self.claims(self.exchange(self.owner, raw))
        self.assertLessEqual(claims['exp'], subject['exp'])
        subject['org_id'] = str(uuid.uuid4())
        other = jwt.encode(subject, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256')
        self.assertEqual(self.exchange(self.owner, other).status_code, 403)
