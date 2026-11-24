import base64
import hashlib

from django.core.exceptions import ValidationError
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from authentication.models import SSOAllowedRedirectURI, SSOAuthorizationCode, User
from authentication.sso_views import _browser_params, _is_redirect_allowed


@override_settings(DEBUG=False, SSO_ALLOWED_REDIRECT_URIS=[])
class LoopbackRedirectTests(APITestCase):
    callbacks = (
        "http://localhost:3000/api/auth/callback",
        "http://127.0.0.1:3000/api/auth/callback",
    )

    def setUp(self):
        self.user = User.objects.create_user("loopback@example.invalid", "synthetic-password", is_active=True)
        self.client_id = "arna-local-dev"
        self.verifier = "a" * 43
        self.challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        for callback in self.callbacks:
            SSOAllowedRedirectURI.objects.create(client_id=self.client_id, redirect_uri=callback)

    def payload(self, callback, **changes):
        return {"client_id": self.client_id, "redirect_uri": callback,
                "code_challenge": self.challenge, "code_challenge_method": "S256",
                "state": "synthetic-state", **changes}

    def authorize(self, payload):
        self.client.force_authenticate(user=self.user)
        return self.client.post(reverse("sso_authorize_code"), payload, format="json")

    def exchange(self, code, callback, **changes):
        self.client.force_authenticate(user=None)
        return self.client.post(reverse("sso_token_exchange"), {
            "grant_type": "authorization_code", "client_id": self.client_id,
            "redirect_uri": callback, "code": code, "code_verifier": self.verifier, **changes,
        }, format="json")

    def test_both_callbacks_support_s256_code_exchange_without_debug(self):
        for callback in self.callbacks:
            with self.subTest(callback=callback):
                self.assertEqual(_browser_params(self.payload(callback))["redirect_uri"], callback)
                response = self.authorize(self.payload(callback))
                self.assertEqual(response.status_code, 201)
                self.assertTrue(response.data["redirect_url"].startswith(callback + "?"))
                self.assertIn("state=synthetic-state", response.data["redirect_url"])
                self.assertEqual(self.exchange(response.data["code"], callback).status_code, 200)
                self.assertEqual(self.exchange(response.data["code"], callback).status_code, 400)

    def test_local_login_page_accepts_registered_callback_without_debug(self):
        for callback in self.callbacks:
            self.assertEqual(self.client.get("/login/", self.payload(callback)).status_code, 200)

    def test_local_code_requires_s256(self):
        response = self.authorize(self.payload(self.callbacks[0], code_challenge_method="plain"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(SSOAuthorizationCode.objects.count(), 0)

    def test_allowlist_is_exact_and_client_bound(self):
        for changes in ({"client_id": "another-client"},
                        {"redirect_uri": "http://localhost:3001/api/auth/callback"},
                        {"redirect_uri": self.callbacks[0] + "/"},
                        {"redirect_uri": self.callbacks[0] + "?next=external"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.authorize(self.payload(self.callbacks[0], **changes)).status_code, 400)
        self.assertEqual(SSOAuthorizationCode.objects.count(), 0)

    def test_legacy_global_list_cannot_grant_http_to_other_clients(self):
        with override_settings(DEBUG=True, SSO_ALLOWED_REDIRECT_URIS=list(self.callbacks)):
            self.assertFalse(_is_redirect_allowed("unregistered-client", self.callbacks[0]))

    def test_inactive_callback_is_rejected(self):
        SSOAllowedRedirectURI.objects.filter(client_id=self.client_id).update(is_active=False)
        self.assertEqual(self.authorize(self.payload(self.callbacks[0])).status_code, 400)
        self.assertEqual(self.client.get("/login/", self.payload(self.callbacks[0])).status_code, 400)

    def test_verifier_and_callback_binding_remain_enforced(self):
        callback = self.callbacks[0]
        code = self.authorize(self.payload(callback)).data["code"]
        self.assertEqual(self.exchange(code, callback, code_verifier="b" * 43).status_code, 400)
        self.assertEqual(self.exchange(code, self.callbacks[1]).status_code, 400)
        self.assertEqual(self.exchange(code, callback, client_id="another-client").status_code, 400)
        self.assertEqual(self.exchange(code, callback).status_code, 200)

    def test_model_rejects_non_loopback_http_and_authority_tricks(self):
        for callback in (
            "http://example.com/api/auth/callback", "http://localhost.evil.example/api/auth/callback",
            "http://localhost@evil.example/api/auth/callback", "http://evil@localhost:3000/api/auth/callback",
            "http://127.0.0.1.evil.example/api/auth/callback", "http://127.0.0.2:3000/api/auth/callback",
            "http://localhost:3000/api/auth/callback#fragment", "http://localhost:0/api/auth/callback",
            "http://localhost:65536/api/auth/callback", "http://localhost:3000/\\evil.example",
        ):
            with self.subTest(callback=callback), self.assertRaises(ValidationError):
                SSOAllowedRedirectURI.objects.create(client_id=self.client_id, redirect_uri=callback)
