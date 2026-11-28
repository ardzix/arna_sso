import uuid
from unittest.mock import Mock, patch

import jwt
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APITestCase

from authentication.crm_session import CRMGrantUserThrottle
from authentication.models import User
from authentication.serializers import MyTokenObtainPairSerializer
from iam.models import Permission, UserPermission
from organization.models import Organization, OrganizationMember


@override_settings(CRM_ARNASITE_TENANTS_URL="https://site.test/tenants/")
class CRMServerSessionTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('crm-server@example.invalid', 'synthetic-password', is_active=True)
        self.owner = User.objects.create_user('crm-owner@example.invalid', 'synthetic-password', is_active=True)
        self.org = Organization.objects.create(name='CRM test', owner=self.owner, package_type='Basic')
        self.member = OrganizationMember.objects.create(user=self.user, organization=self.org)
        self.permission = Permission.objects.create(organization=self.org, name='crm.manage')
        self.grant = UserPermission.objects.create(organization_member=self.member)
        self.grant.permissions.add(self.permission)
        self.tenant = str(uuid.uuid4())
        self.lookup = patch('authentication.crm_proof.requests.get').start()
        self.addCleanup(patch.stopall)
        self.lookup.return_value = Mock(status_code=200)
        self.lookup.return_value.json.return_value = {'results': [{'tenant_id': self.tenant,
            'sso_organization_id': str(self.org.pk), 'is_active': True}]}

    def source(self, **changes):
        token = MyTokenObtainPairSerializer.access_for_user(self.user)
        token['iss'] = settings.DEVICE_TOKEN_ISSUER
        token['app_client_id'] = 'arnasite-dashboard'
        for key, value in changes.items():
            token[key] = value
        return token

    def exchange(self, source=None, body=None):
        return self.client.post('/api/auth/sso/crm-token/', body or {}, format='json',
            HTTP_AUTHORIZATION='Bearer ' + str(source or self.source()))

    def claims(self, response):
        self.assertEqual(response.status_code, 200, response.data)
        return jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
            algorithms=['RS256'], audience='arna-crm', issuer=settings.DEVICE_TOKEN_ISSUER)

    def test_grant_recomputes_permissions_and_tenants_and_bounds_expiry(self):
        source = self.source()
        source['exp'] = source['iat'] + 45
        claims = self.claims(self.exchange(source, {'tenant_ids': [str(uuid.uuid4())], 'is_owner': True, 'permissions': ['forged']}))
        self.assertEqual(claims['organization_id'], str(self.org.pk))
        self.assertEqual(claims['tenant_ids'], [self.tenant])
        self.assertEqual(claims['permissions'], ['crm.manage'])
        self.assertFalse(claims['is_owner'])
        self.assertLessEqual(claims['exp'], source['exp'])

    def test_large_catalogue_is_not_truncated(self):
        permissions = [Permission.objects.create(organization=self.org, name=f'product.{uuid.uuid4()}.manage') for _ in range(108)]
        self.grant.permissions.add(*permissions)
        self.assertEqual(len(self.claims(self.exchange())['permissions']), 109)

    def test_old_subject_token_cannot_restore_removed_permissions(self):
        source = self.source()
        self.grant.permissions.clear()
        self.assertEqual(self.claims(self.exchange(source))['permissions'], [])

    def test_requires_human_bnk_app_issuer_and_primary_audience(self):
        for change in ({'app_client_id': 'another-app'}, {'principal_type': 'service'},
                       {'iss': 'https://wrong.invalid'}, {'aud': 'arna-crm'}, {'device_id': str(uuid.uuid4())},
                       {'tenant_ids': [self.tenant]}):
            with self.subTest(change=change):
                self.assertIn(self.exchange(self.source(**change)).status_code, (401, 403))
        self.lookup.assert_not_called()

    def test_missing_or_changed_active_organization_is_denied(self):
        self.assertEqual(self.exchange(self.source(org_id=str(uuid.uuid4()))).status_code, 403)
        self.member.is_session_active = False
        self.member.save(update_fields=['is_session_active'])
        self.assertEqual(self.exchange().status_code, 403)
        self.lookup.assert_not_called()

    def test_site_failure_is_503_without_access_or_refresh(self):
        self.lookup.return_value.status_code = 503
        response = self.exchange()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('access_token', response.data)
        self.assertNotIn('refresh', response.data)

    def test_unauthenticated_requests_are_denied(self):
        self.assertIn(self.client.post('/api/auth/sso/crm-token/', {}).status_code, (401, 403))
        self.lookup.assert_not_called()

    def test_user_throttle_is_dedicated_and_bounded(self):
        with patch.object(CRMGrantUserThrottle, 'rate', '1/min'):
            self.assertEqual(self.exchange().status_code, 200)
            self.assertEqual(self.exchange().status_code, 429)
