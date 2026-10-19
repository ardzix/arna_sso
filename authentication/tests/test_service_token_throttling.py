from unittest.mock import patch

from django.core.cache import cache
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.tokens import UntypedToken

from authentication.models import ServiceAccount
from authentication.service_throttles import (
    AuthenticatedServiceTokenThrottle, ServiceTokenFailureThrottle, ServiceTokenIPThrottle,
)


class ServiceTokenThrottleTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.service = ServiceAccount(name='CRM rate test', client_id='rate-test-crm',
                                      audiences=['arna-commerce'], scopes=['commerce.entitlements.read:arna-crm'])
        self.service.set_client_secret('isolated-only-secret')
        self.service.save()
        self.payload = {'client_id': self.service.client_id, 'client_secret': 'isolated-only-secret',
                        'audience': 'arna-commerce'}
        self.url = reverse('service_token')

    def tearDown(self):
        cache.clear()

    def post(self, **changes):
        return self.client.post(self.url, {**self.payload, **changes}, format='json')

    def test_generic_anonymous_exhaustion_does_not_block_a_valid_service(self):
        with patch.object(AnonRateThrottle, 'allow_request', return_value=False):
            response = self.post()
        self.assertEqual(response.status_code, 200)
        token = UntypedToken(response.data['access'])
        self.assertEqual(token['aud'], 'arna-commerce')
        self.assertEqual(token['scopes'], self.service.scopes)

    def test_verified_client_budget_is_bounded_and_has_retry_after(self):
        with patch.object(AuthenticatedServiceTokenThrottle, 'get_rate', return_value='2/minute'):
            self.assertEqual(self.post().status_code, 200)
            self.assertEqual(self.post().status_code, 200)
            response = self.post()
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response['Retry-After']), 0)
        self.assertNotIn('access', response.data)

    def test_success_budget_isolated_from_another_verified_client(self):
        other = ServiceAccount(name='Other rate client', client_id='rate-other',
                               audiences=['arna-commerce'], scopes=['commerce.entitlements.read:other'])
        other.set_client_secret('other-test-secret'); other.save()
        with patch.object(AuthenticatedServiceTokenThrottle, 'get_rate', return_value='1/minute'):
            self.assertEqual(self.post().status_code, 200)
            self.assertEqual(self.post().status_code, 429)
            self.assertEqual(self.post(client_id=other.client_id, client_secret='other-test-secret').status_code, 200)

    def test_invalid_secret_budget_rejects_without_issuing_token(self):
        with patch.object(ServiceTokenFailureThrottle, 'get_rate', return_value='2/minute'):
            self.assertEqual(self.post(client_secret='wrong').status_code, 401)
            self.assertEqual(self.post(client_secret='wrong').status_code, 401)
            response = self.post(client_secret='wrong')
        self.assertEqual(response.status_code, 429)
        self.assertNotIn('access', response.data)

    def test_valid_exchanges_do_not_consume_failed_secret_budget(self):
        with patch.object(ServiceTokenFailureThrottle, 'get_rate', return_value='1/minute'):
            self.assertEqual(self.post().status_code, 200)
            self.assertEqual(self.post().status_code, 200)
            self.assertEqual(self.post(client_secret='wrong').status_code, 401)
            self.assertEqual(self.post(client_secret='wrong').status_code, 429)

    def test_forged_client_names_cannot_evade_endpoint_ip_budget(self):
        with patch.object(ServiceTokenIPThrottle, 'get_rate', return_value='2/minute'):
            self.assertEqual(self.post(client_id='not-a-service-1').status_code, 401)
            self.assertEqual(self.post(client_id='not-a-service-2').status_code, 401)
            self.assertEqual(self.post(client_id='not-a-service-3').status_code, 429)

    def test_invalid_secret_cannot_spend_authenticated_client_budget(self):
        with patch.object(AuthenticatedServiceTokenThrottle, 'get_rate', return_value='1/minute'):
            self.assertEqual(self.post(client_secret='wrong').status_code, 401)
            self.assertEqual(self.post().status_code, 200)

    def test_invalid_audience_and_inactive_account_still_reject(self):
        self.assertEqual(self.post(audience='storage').status_code, 400)
        self.service.is_active = False
        self.service.save(update_fields=['is_active'])
        response = self.post()
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('access', response.data)

    def test_ip_budget_recovers_after_its_window(self):
        with patch.object(ServiceTokenIPThrottle, 'get_rate', return_value='1/minute'):
            with patch.object(ServiceTokenIPThrottle, 'timer', return_value=100):
                self.assertEqual(self.post().status_code, 200)
                self.assertEqual(self.post().status_code, 429)
            with patch.object(ServiceTokenIPThrottle, 'timer', return_value=161):
                self.assertEqual(self.post().status_code, 200)
