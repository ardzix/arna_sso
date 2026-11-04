import hashlib
import json
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase
from django.utils import timezone
from rest_framework.test import APIClient

from authentication.device_throttles import AUTHORIZE_PATH, load_exemption


class DeviceAuthorizeThrottleTests(SimpleTestCase):
    ip = "203.0.113.51"
    marker = "a" * 64

    def setUp(self):
        now = timezone.now()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "policy.json"
        self.policy = {
            "ip": self.ip, "sha256": hashlib.sha256(self.marker.encode()).hexdigest(),
            "starts_at": (now - timedelta(days=1)).isoformat(),
            "expires_at": (now + timedelta(days=6)).isoformat(),
        }
        self.write_policy()
        self.patch = patch("authentication.device_throttles.EXEMPTION_PATH", self.file)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        cache.clear()
        self.addCleanup(cache.clear)
        self.addCleanup(load_exemption.cache_clear)
        cache.set("throttle_anon_" + self.ip, [now.timestamp()] * 100)
        self.client = APIClient()

    def write_policy(self):
        self.file.write_text(json.dumps(self.policy), encoding="utf-8")
        load_exemption.cache_clear()

    def post(self, *, marker=None, real_ip=None, path=AUTHORIZE_PATH):
        return self.client.post(path, {}, format="json", HTTP_X_FORWARDED_FOR=self.ip,
                                HTTP_X_REAL_IP=real_ip or self.ip,
                                HTTP_X_ARNA_DEVICE_EXEMPTION=self.marker if marker is None else marker)

    def test_only_attested_ip_skips_daily_quota(self):
        self.assertEqual(self.post().status_code, 400)  # Reaches normal validation.
        self.assertEqual(self.post(marker="b" * 64).status_code, 429)
        self.assertEqual(self.post(real_ip="203.0.113.52").status_code, 429)
        self.assertEqual(self.post(marker="").status_code, 429)

    def test_expiry_and_invalid_policy_fail_closed(self):
        self.policy["expires_at"] = timezone.now().isoformat()
        self.write_policy()
        self.assertEqual(self.post().status_code, 429)
        self.policy["expires_at"] = (timezone.now() + timedelta(days=10)).isoformat()
        self.write_policy()
        self.assertEqual(self.post().status_code, 429)

    def test_per_minute_limit_remains(self):
        cache.set("throttle_login_attempt_" + self.ip, [timezone.now().timestamp()] * 10)
        response = self.post()
        self.assertEqual(response.status_code, 429)
        self.assertLessEqual(int(response["Retry-After"]), 60)

    def test_legacy_alias_cannot_use_exemption(self):
        self.assertEqual(self.post(path="/api/auth/device/authorize/").status_code, 429)
