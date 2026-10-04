from unittest.mock import patch

from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from authentication.wa_views import WAReverseSendOTPView, WAVerifyOTPView


class WhatsAppOTPThrottleTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def test_otp_views_do_not_inherit_shared_ip_throttles(self):
        for view in (WAReverseSendOTPView, WAVerifyOTPView):
            with self.subTest(view=view.__name__):
                self.assertEqual(view().get_throttles(), [])

    def test_invalid_requests_are_still_validated_when_anon_quota_is_exhausted(self):
        with patch.object(AnonRateThrottle, 'allow_request', return_value=False):
            for view in (WAReverseSendOTPView, WAVerifyOTPView):
                with self.subTest(view=view.__name__):
                    response = view.as_view()(self.factory.post('/', {}, format='json'))
                    self.assertEqual(response.status_code, 400)
                    self.assertIn('phone', response.data)

    def test_options_remains_accessible_when_anon_quota_is_exhausted(self):
        with patch.object(AnonRateThrottle, 'allow_request', return_value=False):
            for view in (WAReverseSendOTPView, WAVerifyOTPView):
                with self.subTest(view=view.__name__):
                    response = view.as_view()(self.factory.options('/'))
                    self.assertEqual(response.status_code, 200)

    def test_default_throttles_remain_enabled_for_other_api_views(self):
        self.assertTrue(APIView().get_throttles())
