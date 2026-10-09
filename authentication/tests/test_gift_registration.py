import time
import uuid
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import skipUnless
from io import StringIO

import jwt
from django.conf import settings
from django.db import connection, close_old_connections
from django.test import TransactionTestCase
from django.core.management import call_command
from django.core.management.base import CommandError
from rest_framework.throttling import AnonRateThrottle
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken, UntypedToken

from authentication.gift_registration import AUDIENCE, SCOPE, register_identity, RegistrationConflict
from authentication.models import ServiceAccount, TrustedRegistration, User
from user_profile.models import UserProfile


class GiftRegistrationTests(APITestCase):
    def setUp(self):
        self.service = ServiceAccount(name="Synthetic OLS gift", client_id="synthetic-ols-gift",
                                      scopes=[SCOPE], audiences=[AUDIENCE])
        self.service.set_client_secret("synthetic-test-only-secret")
        self.service.save()
        self.url = reverse("trusted_whatsapp_registration")
        self.data = {"phone": "6280000000001", "name": "Test Gift", "campaign": "synthetic-wedding", "message_id": "synthetic-message-1"}
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.token())

    def token(self, **changes):
        token = AccessToken()
        token["iss"] = settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id"
        token["aud"] = AUDIENCE
        token["token_type"] = "service"
        token["principal_type"] = "service"
        token["scopes"] = [SCOPE]
        token["scope"] = SCOPE
        token["service_id"] = str(self.service.pk)
        token["client_id"] = self.service.client_id
        token["exp"] = token["iat"] + 300
        for key, value in changes.items():
            token[key] = value
        return str(token)

    def test_register_creates_name_without_login_privileges_or_otp(self):
        with patch("authentication.signals.async_task") as send:
            response = self.client.post(self.url, self.data, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["status"], "registered")
        user = User.objects.get(pk=response.data["user_id"])
        self.assertEqual(user.phone_number, self.data["phone"])
        self.assertEqual(user.profile.full_name, "Test Gift")
        self.assertFalse(user.is_active)
        self.assertFalse(user.phone_verified)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.has_usable_password())
        self.assertIsNone(user.otp)
        self.assertFalse(user.groups.exists())
        self.assertFalse(user.user_permissions.exists())
        self.assertFalse(send.called)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    def test_retries_and_new_messages_do_not_duplicate_identity(self):
        first = self.client.post(self.url, self.data, format="json")
        replay = self.client.post(self.url, self.data, format="json")
        later = self.client.post(self.url, {**self.data, "message_id": "synthetic-message-2"}, format="json")
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.data["replayed"])
        self.assertEqual(later.status_code, 200)
        self.assertFalse(later.data["created"])
        self.assertEqual(first.data["user_id"], later.data["user_id"])
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(TrustedRegistration.objects.count(), 2)

    def test_existing_account_and_profile_are_never_overwritten(self):
        user = User.objects.create_user(email="existing@example.test", password="synthetic-password",
                                        phone_number=self.data["phone"], is_active=True, phone_verified=True,
                                        otp="123456", mfa_secret="UNCHANGED")
        UserProfile.objects.create(user=user, full_name="Existing Name", phone_number=self.data["phone"])
        original = (user.password, user.otp, user.mfa_secret)
        response = self.client.post(self.url, self.data, format="json")
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertEqual((user.password, user.otp, user.mfa_secret), original)
        self.assertTrue(user.is_active)
        self.assertTrue(user.phone_verified)
        self.assertEqual(user.profile.full_name, "Existing Name")

    def test_idempotency_key_cannot_be_rebound_to_different_data(self):
        self.client.post(self.url, self.data, format="json")
        for changes in ({"phone": "6280000000002"}, {"name": "Other Name"}):
            response = self.client.post(self.url, {**self.data, **changes}, format="json")
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.data["error"], "registration_conflict")
        self.assertEqual(User.objects.count(), 1)

    def test_email_collision_does_not_take_over_existing_identity(self):
        user = User.objects.create_user(email=f"wa_{self.data['phone']}@arnatech.local", password=None)
        response = self.client.post(self.url, self.data, format="json")
        self.assertEqual(response.status_code, 409)
        user.refresh_from_db()
        self.assertIsNone(user.phone_number)
        self.assertEqual(TrustedRegistration.objects.count(), 0)

    def test_no_auth_and_user_refresh_device_or_wrong_audience_are_rejected(self):
        self.client.credentials()
        self.assertEqual(self.client.post(self.url, self.data, format="json").status_code, 401)
        for changes in ({"token_type": "access"}, {"token_type": "refresh"}, {"token_type": "device"},
                        {"aud": "storage"}, {"scopes": ["admin"]}, {"client_id": "other"},
                        {"exp": int(time.time()) - 10}, {"exp": int(time.time()) + 600}):
            self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.token(**changes))
            self.assertEqual(self.client.post(self.url, self.data, format="json").status_code, 401)
        forged = jwt.encode({"exp": int(time.time()) + 60}, "synthetic-wrong-key", algorithm="HS256")
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + forged)
        self.assertEqual(self.client.post(self.url, self.data, format="json").status_code, 401)
        self.assertEqual(User.objects.count(), 0)

    def test_account_revocation_takes_effect_before_token_expiry(self):
        self.service.is_active = False
        self.service.save(update_fields=["is_active"])
        self.assertEqual(self.client.post(self.url, self.data, format="json").status_code, 401)

    def test_unicode_and_canonical_phone_validation_and_no_mass_assignment(self):
        for changes in ({"phone": "0812345"}, {"phone": "+6280000000001"}, {"name": "<script>"},
                        {"name": "123"}, {"name": "A\nB"}, {"is_staff": True}, {"org_id": str(uuid.uuid4())}):
            self.assertEqual(self.client.post(self.url, {**self.data, **changes}, format="json").status_code, 400)
        self.assertEqual(User.objects.count(), 0)
        response = self.client.post(self.url, {**self.data, "name": "Nur A’isyah"}, format="json")
        self.assertEqual(response.status_code, 201)

    def test_service_token_exchange_preserves_legacy_response_and_is_narrow(self):
        self.client.credentials()
        data = {"client_id": self.service.client_id, "client_secret": "synthetic-test-only-secret", "audience": AUDIENCE}
        response = self.client.post(reverse("service_token"), data, format="json")
        self.assertEqual(response.status_code, 200)
        token = UntypedToken(response.data["access"])
        self.assertEqual(token["token_type"], "service")
        self.assertEqual(token["scope"], SCOPE)
        self.assertEqual(token["aud"], AUDIENCE)
        self.service.scopes.append("admin")
        self.service.save(update_fields=["scopes"])
        self.assertEqual(self.client.post(reverse("service_token"), data, format="json").status_code, 400)

    def test_dedicated_token_exchange_is_not_blocked_by_the_shared_otp_quota(self):
        self.client.credentials()
        data = {"client_id": self.service.client_id, "client_secret": "synthetic-test-only-secret", "audience": AUDIENCE}
        with patch.object(AnonRateThrottle, 'allow_request', return_value=False):
            response = self.client.post(reverse("registration_service_token"), data, format="json")
        self.assertEqual(response.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + response.data["access"])
        self.assertEqual(self.client.post(self.url, self.data, format="json").status_code, 201)
        self.client.credentials()
        self.assertEqual(self.client.post(reverse("registration_service_token"), {**data, "client_secret": "wrong"}, format="json").status_code, 401)
        self.assertEqual(self.client.post(reverse("registration_service_token"), {**data, "audience": "storage"}, format="json").status_code, 400)

    def test_provisioning_never_prints_a_secret_or_rotates_existing_client(self):
        output = StringIO()
        secret = "synthetic-" + "x" * 48
        with patch("sys.stdin", StringIO(secret)):
            call_command("create_gift_registration_service", secret_stdin=True, stdout=output)
        self.assertNotIn(secret, output.getvalue())
        service = ServiceAccount.objects.get(client_id="ols-wedding-gift-n8n")
        self.assertTrue(service.check_client_secret(secret))
        self.assertEqual(service.scopes, [SCOPE])
        self.assertEqual(service.audiences, [AUDIENCE])
        with patch("sys.stdin", StringIO("y" * 60)), self.assertRaises(CommandError):
            call_command("create_gift_registration_service", secret_stdin=True, stdout=output)
        service.refresh_from_db()
        self.assertTrue(service.check_client_secret(secret))


@skipUnless(connection.vendor == "postgresql", "Concurrency is verified only on PostgreSQL.")
class GiftRegistrationConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.service = ServiceAccount.objects.create(name="Synthetic concurrency", client_id="synthetic-concurrent", scopes=[SCOPE], audiences=[AUDIENCE])
        self.data = {"phone": "6280000000003", "name": "Synthetic Race", "campaign": "synthetic-race", "message_id": "synthetic-message"}

    def concurrent(self, payloads):
        barrier = Barrier(len(payloads))
        def invoke(data):
            close_old_connections()
            try:
                service = ServiceAccount.objects.get(pk=self.service.pk)
                barrier.wait(timeout=10)
                try:
                    return register_identity(service, data)
                except RegistrationConflict:
                    return "conflict"
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=len(payloads)) as pool:
            return list(pool.map(invoke, payloads))

    def test_same_proof_and_phone_are_atomic(self):
        results = self.concurrent([self.data] * 4)
        self.assertNotIn("conflict", results)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(TrustedRegistration.objects.count(), 1)
        self.assertEqual(sum(not result[2] for result in results), 1)

    def test_distinct_messages_for_same_phone_still_create_one_user(self):
        results = self.concurrent([{**self.data, "message_id": f"synthetic-{i}"} for i in range(4)])
        self.assertNotIn("conflict", results)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(TrustedRegistration.objects.count(), 4)
        self.assertEqual(sum(result[1] for result in results), 1)

    def test_racing_rebound_proof_rolls_back_the_losing_identity(self):
        results = self.concurrent([self.data, {**self.data, "phone": "6280000000004"}])
        self.assertEqual(results.count("conflict"), 1)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(TrustedRegistration.objects.count(), 1)
