import uuid

import jwt
from django.conf import settings
from rest_framework.test import APITestCase

from authentication.serializers import MyTokenObtainPairSerializer
from authentication.tests.test_device_iam import DeviceIAMTests
from iam.effective import LEVELUP_PERMISSIONS


class HumanLevelUpTests(APITestCase):
    setUp = DeviceIAMTests.setUp
    pair = DeviceIAMTests.pair

    def exchange(self, user, raw=None):
        self.client.force_authenticate(user=None)
        raw = raw or str(MyTokenObtainPairSerializer.get_token(user).access_token)
        return self.client.post(
            '/api/v1/devices/resource-token/', {'audience': 'arna-levelup'},
            format='json', HTTP_AUTHORIZATION='Bearer ' + raw,
        )

    def test_owner_receives_only_levelup_permissions_for_verified_active_tenant(self):
        response = self.exchange(self.owner)
        self.assertEqual(response.status_code, 200, response.data)
        claims = jwt.decode(
            response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
            algorithms=['RS256'], issuer=settings.DEVICE_TOKEN_ISSUER, audience='arna-levelup',
        )
        self.assertEqual(claims['tenant_id'], str(self.tenant))
        self.assertEqual(claims['organization_id'], str(self.org.pk))
        self.assertEqual(set(claims['permissions']), LEVELUP_PERMISSIONS)
        self.assertEqual(claims['principal_type'], 'user')
        self.assertEqual(claims['token_type'], 'resource_access')
        self.assertNotIn('tenant_ids', claims)
        self.assertEqual(self.exchange(self.owner, response.data['access_token']).status_code, 401)

    def test_staff_and_device_have_no_implied_access(self):
        self.assertEqual(self.exchange(self.staff).status_code, 403)
        self.assertEqual(self.exchange(self.owner, self.pair()['access_token']).status_code, 403)

    def test_missing_revoked_and_stale_workspace_are_denied(self):
        self.lookup.return_value.json.return_value = {'results': []}
        self.assertEqual(self.exchange(self.owner).status_code, 400)
        self.member.active_tenant_id = self.tenant
        self.member.save(update_fields=['active_tenant_id'])
        self.assertEqual(self.exchange(self.owner).status_code, 403)
        raw = str(MyTokenObtainPairSerializer.get_token(self.owner).access_token)
        claims = jwt.decode(raw, settings.SIMPLE_JWT['VERIFYING_KEY'], algorithms=['RS256'],
                            options={'verify_aud': False})
        claims['tenant_id'] = str(uuid.uuid4())
        self.assertEqual(self.exchange(self.owner, jwt.encode(
            claims, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='RS256',
        )).status_code, 403)
