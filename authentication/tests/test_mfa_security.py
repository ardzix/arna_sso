from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

import pyotp
from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.tokens import AccessToken, UntypedToken

from authentication.mfa import begin_enrollment, verify_factor
from authentication.models import MFAState, User
from authentication.serializers import PreAuthTokenSerializer
from audit_logging.models import AuditLog


class MFASecurityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email="mfa@example.test", password="synthetic-password", is_active=True)
        self.client = APIClient()

    def enable(self):
        self.user.mfa_secret = pyotp.random_base32()
        self.user.mfa_enabled = True
        self.user.save()

    def challenge(self):
        return PreAuthTokenSerializer.get_token(self.user)

    def verify(self, token=None, code=None):
        return self.client.post(reverse("mfa_verify"), {
            "token": token or self.challenge(),
            "mfa_token": code or pyotp.TOTP(self.user.mfa_secret).now(),
        }, format="json")

    def setup_pending(self):
        self.client.force_authenticate(self.user)
        response = self.client.post(reverse("set_mfa"))
        self.assertEqual(response.status_code, 200)
        return response.data["mfa_secret"]

    def test_setup_does_not_activate_mfa_or_change_first_factor(self):
        secret = self.setup_pending()
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_secret)
        self.assertFalse(self.user.mfa_enabled)
        self.assertEqual(MFAState.objects.get(user=self.user).pending_secret, secret)
        self.client.force_authenticate(None)
        response = self.client.post(reverse("login"), {"email": self.user.email, "password": "synthetic-password"})
        self.assertIn("access", response.data)

    def test_pending_setup_is_stable_and_expires(self):
        first = self.setup_pending()
        self.assertEqual(first, self.setup_pending())
        MFAState.objects.filter(user=self.user).update(pending_expires_at=timezone.now() - timedelta(seconds=1))
        self.assertNotEqual(first, self.setup_pending())

    def test_confirmation_requires_authentication(self):
        self.assertIn(self.client.post(reverse("mfa_confirm"), {"mfa_token": "123456"}).status_code, (401, 403))

    def test_confirmation_enables_only_requesting_user_and_does_not_issue_login_tokens(self):
        other = User.objects.create_user(email="other@example.test", is_active=True)
        secret = self.setup_pending()
        response = self.client.post(reverse("mfa_confirm"), {"mfa_token": pyotp.TOTP(secret).now(), "user_id": str(other.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("access", response.data)
        self.user.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual(self.user.mfa_secret, secret)
        self.assertTrue(self.user.mfa_enabled)
        self.assertFalse(other.mfa_secret)
        self.assertFalse(MFAState.objects.get(user=self.user).pending_secret)

    def test_old_profile_confirmation_payload_remains_compatible(self):
        secret = self.setup_pending()
        response = self.client.post(reverse("mfa_verify"), {"mfa_token": pyotp.TOTP(secret).now()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["mfa_enabled"], True)
        self.assertNotIn("access", response.data)

    def test_bad_confirmation_does_not_activate_and_consumes_attempt(self):
        self.setup_pending()
        response = self.client.post(reverse("mfa_confirm"), {"mfa_token": "invalid"})
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_secret)
        self.assertEqual(MFAState.objects.get(user=self.user).attempts, 1)

    def test_expired_enrollment_cannot_be_confirmed(self):
        secret = self.setup_pending()
        MFAState.objects.filter(user=self.user).update(pending_expires_at=timezone.now() - timedelta(seconds=1))
        response = self.client.post(reverse("mfa_confirm"), {"mfa_token": pyotp.TOTP(secret).now()})
        self.assertEqual(response.data["error"], "enrollment_expired")

    def test_enabled_factor_cannot_be_overwritten_by_setup(self):
        self.enable()
        original = self.user.mfa_secret
        self.client.force_authenticate(self.user)
        self.assertEqual(self.client.post(reverse("set_mfa")).status_code, 400)
        self.user.refresh_from_db()
        self.assertEqual(self.user.mfa_secret, original)

    def test_valid_login_bypasses_exhausted_generic_anon_quota(self):
        self.enable()
        with patch.object(AnonRateThrottle, "allow_request", return_value=False):
            response = self.verify()
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)

    def test_failures_share_account_budget_across_new_challenges_and_clients(self):
        self.enable()
        for _ in range(5):
            self.assertEqual(self.verify(code="bad").status_code, 400)
            self.client = APIClient()
        response = self.verify()
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response["Retry-After"]), 0)

    def test_rate_limit_window_recovers(self):
        self.enable()
        for _ in range(5):
            self.verify(code="bad")
        MFAState.objects.filter(user=self.user).update(window_started_at=timezone.now() - timedelta(seconds=61))
        self.assertEqual(self.verify().status_code, 200)

    def test_account_limits_are_independent_on_same_ip(self):
        self.enable()
        for _ in range(6):
            self.verify(code="bad")
        other = User.objects.create_user(email="independent@example.test", is_active=True, mfa_secret=pyotp.random_base32(), mfa_enabled=True)
        response = self.verify(token=PreAuthTokenSerializer.get_token(other), code=pyotp.TOTP(other.mfa_secret).now())
        self.assertEqual(response.status_code, 200)

    def test_otp_replay_is_rejected_even_for_new_challenge(self):
        self.enable()
        self.assertEqual(self.verify().status_code, 200)
        self.assertEqual(self.verify().data["error"], "invalid_mfa_code")

    def test_challenge_is_single_use_even_with_a_new_totp_counter(self):
        self.enable()
        token = self.challenge()
        self.assertEqual(self.verify(token=token).status_code, 200)
        with patch("authentication.mfa.matching_counter", return_value=10**12):
            response = self.verify(token=token)
        self.assertEqual(response.status_code, 401)

    def test_reset_invalidates_existing_challenge(self):
        self.enable()
        token = self.challenge()
        old_code = pyotp.TOTP(self.user.mfa_secret).now()
        self.user.mfa_secret = None
        self.user.mfa_enabled = False
        self.user.save()
        self.assertEqual(self.verify(token=token, code=old_code).status_code, 401)

    def test_reenrollment_invalidates_previous_factor_challenge(self):
        self.enable()
        token = self.challenge()
        self.user.mfa_secret = pyotp.random_base32()
        self.user.save()
        self.assertEqual(self.verify(token=token).status_code, 401)

    def test_inactive_account_cannot_verify(self):
        self.enable()
        token = self.challenge()
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.verify(token=token).status_code, 401)

    def test_wrong_token_type_and_unsigned_junk_are_rejected(self):
        self.enable()
        for token in ("not-a-jwt", str(AccessToken.for_user(self.user))):
            self.assertEqual(self.verify(token=token).status_code, 401)

    def test_expired_challenge_cannot_verify(self):
        self.enable()
        token = UntypedToken(self.challenge())
        token["exp"] = int(timezone.now().timestamp()) - 60
        self.assertEqual(self.verify(token=str(token)).status_code, 401)

    def test_json_arrays_are_client_errors(self):
        self.assertEqual(self.client.post(reverse("mfa_verify"), [], format="json").status_code, 400)
        self.client.force_authenticate(self.user)
        self.assertEqual(self.client.post(reverse("mfa_confirm"), [], format="json").status_code, 400)

    def test_invalid_challenges_have_their_own_shared_ip_limit(self):
        self.enable()
        for _ in range(30):
            self.assertEqual(self.verify(token="invalid").status_code, 401)
        self.assertEqual(self.verify(token="invalid").status_code, 429)
        self.assertEqual(self.verify().status_code, 200)

    def test_audit_does_not_contain_secrets_codes_or_tokens(self):
        secret = self.setup_pending()
        self.client.post(reverse("mfa_confirm"), {"mfa_token": pyotp.TOTP(secret).now()})
        metadata = list(AuditLog.objects.filter(user=self.user).values_list("metadata", flat=True))
        self.assertTrue(metadata)
        self.assertTrue(all(value == {} for value in metadata))


class MFAConcurrencyTests(TransactionTestCase):
    def test_two_workers_cannot_consume_same_factor(self):
        if connection.vendor != "postgresql":
            self.skipTest("Requires real PostgreSQL row locks")
        user = User.objects.create_user(email="race@example.test", is_active=True, mfa_secret=pyotp.random_base32(), mfa_enabled=True)
        token = UntypedToken(PreAuthTokenSerializer.get_token(user))
        code = pyotp.TOTP(user.mfa_secret).now()

        def attempt(_):
            close_old_connections()
            try:
                return verify_factor(user.pk, code, challenge=token)[0]
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(results.count(None), 1)
        self.assertEqual(results.count("invalid_session"), 1)

    def test_parallel_workers_cannot_exceed_account_budget(self):
        if connection.vendor != "postgresql":
            self.skipTest("Requires real PostgreSQL row locks")
        user = User.objects.create_user(email="budget-race@example.test", is_active=True, mfa_secret=pyotp.random_base32(), mfa_enabled=True)
        token = UntypedToken(PreAuthTokenSerializer.get_token(user))

        def attempt(_):
            close_old_connections()
            try:
                return verify_factor(user.pk, "invalid", challenge=token)[0]
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=7) as pool:
            results = list(pool.map(attempt, range(7)))
        self.assertEqual(results.count("invalid_mfa_code"), 5)
        self.assertEqual(results.count("throttled"), 2)
