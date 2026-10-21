import uuid
from unittest.mock import patch
import jwt
from django.conf import settings
from rest_framework.test import APITestCase
from rest_framework.exceptions import AuthenticationFailed
from authentication.device_security import device_token_registration
from authentication.models import DeviceRegistration
from authentication.device_views import _device_access_token
from authentication.tests.test_device_iam import DeviceIAMTests
from iam.models import Permission, DeviceRole


class DeviceCommerceTests(APITestCase):
    setUp = DeviceIAMTests.setUp
    pair = DeviceIAMTests.pair
    assign = DeviceIAMTests.assign

    def commerce_token(self, token, audience='arna-commerce'):
        self.client.force_authenticate(user=None)
        return self.client.post('/api/v1/devices/resource-token/', {'audience': audience}, format='json',
                                HTTP_AUTHORIZATION='Bearer ' + token)

    def enable_checkout(self, pair):
        permissions = Permission.objects.filter(organization=self.org,
            name__in=['commerce.orders.read', 'commerce.orders.write', 'commerce.payments.create'])
        self.role.permissions.add(*permissions)
        self.assign(pair)

    def test_checkout_token_filters_storage_and_event_processing_and_preserves_identity(self):
        pair = self.pair()
        self.assertEqual(self.commerce_token(pair['access_token']).status_code, 403)
        self.enable_checkout(pair)
        process = Permission.objects.create(organization=self.org, name='commerce.payments.process')
        self.role.permissions.add(process)
        response = self.commerce_token(pair['access_token'])
        self.assertEqual(response.status_code, 200, response.data)
        claims = jwt.decode(response.data['access_token'], settings.SIMPLE_JWT['VERIFYING_KEY'],
            algorithms=['RS256'], audience='arna-commerce', issuer=settings.DEVICE_TOKEN_ISSUER)
        self.assertEqual(claims['permissions'], ['commerce.orders.read', 'commerce.orders.write', 'commerce.payments.create'])
        self.assertEqual(claims['scopes'], claims['permissions'])
        self.assertEqual(claims['source_audience'], 'photobooth-api')
        self.assertEqual(claims['device_id'], pair['device_id'])
        self.assertEqual(claims['tenant_id'], str(self.tenant))
        self.assertFalse(claims['is_owner'])
        self.assertEqual(device_token_registration(response.data['access_token'], 'arna-commerce')[0].pk, uuid.UUID(pair['device_id']))
        self.assertEqual(self.commerce_token(pair['access_token'], 'not-allowed').status_code, 400)

    def test_current_iam_and_revoke_are_checked_without_changing_pairing_scopes(self):
        pair = self.pair()
        self.enable_checkout(pair)
        token = self.commerce_token(pair['access_token']).data['access_token']
        with self.assertRaises(AuthenticationFailed):
            device_token_registration(token, 'storage')
        self.role.permissions.remove(Permission.objects.get(organization=self.org, name='commerce.orders.write'))
        with self.assertRaises(AuthenticationFailed):
            device_token_registration(token, 'arna-commerce')
        self.assertEqual(device_token_registration(pair['access_token'], 'photobooth-api')[1]['scopes'], ['photobooth.session'])
        fresh = self.commerce_token(pair['access_token'])
        self.assertEqual(fresh.status_code, 200)
        DeviceRegistration.objects.filter(pk=pair['device_id']).update(is_active=False)
        self.assertEqual(self.commerce_token(pair['access_token']).status_code, 401)

    def test_catalog_is_seeded_but_no_automatic_device_grants_or_commerce_pairing_scopes(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post('/api/v1/devices/resource-token/', {'audience': 'arna-commerce'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        pair = self.pair()
        self.assertEqual(Permission.objects.filter(organization=self.org, name__startswith='commerce.').count(), 6)
        self.assertFalse(DeviceRole.objects.exists())
        self.client.force_authenticate(user=None)
        response = self.client.post('/api/v1/devices/authorize/', {'client_id': 'invalid-commerce-pair',
            'device_name': 'Invalid scope', 'audience': 'photobooth-api',
            'scopes': ['photobooth.session', 'commerce.orders.write', 'commerce.payments.process']}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_other_resource_devices_cannot_exchange_checkout_tokens(self):
        pair = self.pair()
        self.enable_checkout(pair)
        device = DeviceRegistration.objects.get(pk=pair['device_id'])
        device.audience = 'scanner-api'
        device.save()
        with patch.object(settings, 'DEVICE_ALLOWED_AUDIENCES', ['photobooth-api', 'scanner-api']), \
             patch.object(settings, 'DEVICE_AUDIENCE_SCOPES', {'photobooth-api': ['photobooth.session'], 'scanner-api': ['photobooth.session']}):
            self.assertEqual(self.commerce_token(_device_access_token(device)).status_code, 403)
