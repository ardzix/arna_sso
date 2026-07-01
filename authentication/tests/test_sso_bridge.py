import base64
import hashlib

from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from authentication.models import SSOAllowedRedirectURI, SSOAuthorizationCode, User


def pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@override_settings(
    SSO_ALLOWED_REDIRECT_URIS=["https://sales.ourlilstudio.com/auth/callback"],
    SSO_AUTH_CODE_LIFETIME_SECONDS=300,
)
class SSOBridgeTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="sso-user@example.com",
            password="testpassword",
            is_active=True,
        )
        self.authorize_url = reverse("sso_authorize_code")
        self.token_url = reverse("sso_token_exchange")
        self.redirect_uri = "https://sales.ourlilstudio.com/auth/callback"
        self.client_id = "ols-mp"
        self.verifier = "a" * 43
        self.challenge = pkce_challenge(self.verifier)

    def allow_redirect_in_db(self, is_active=True):
        return SSOAllowedRedirectURI.objects.create(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            is_active=is_active,
        )

    def authorize_code(self):
        self.client.force_authenticate(user=self.user)
        return self.client.post(
            self.authorize_url,
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "code_challenge": self.challenge,
                "code_challenge_method": "S256",
                "state": "csrf-state",
            },
            format="json",
        )

    def exchange_code(self, code, verifier=None):
        self.client.force_authenticate(user=None)
        return self.client.post(
            self.token_url,
            {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "code": code,
                "code_verifier": verifier or self.verifier,
            },
            format="json",
        )

    def test_authorize_code_requires_allowed_redirect_uri(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            self.authorize_url,
            {
                "client_id": self.client_id,
                "redirect_uri": "https://evil.example.com/auth/callback",
                "code_challenge": self.challenge,
                "code_challenge_method": "S256",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(SSOAuthorizationCode.objects.count(), 0)

    def test_authorize_code_returns_redirect_url(self):
        response = self.authorize_code()

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("code", response.data)
        self.assertTrue(response.data["redirect_url"].startswith(self.redirect_uri))
        self.assertIn("state=csrf-state", response.data["redirect_url"])
        self.assertEqual(SSOAuthorizationCode.objects.count(), 1)

    def test_token_exchange_returns_jwt_and_marks_code_used(self):
        code = self.authorize_code().data["code"]

        response = self.exchange_code(code)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertEqual(response.data["token_type"], "Bearer")
        self.assertTrue(SSOAuthorizationCode.objects.get().is_used())

    def test_token_exchange_rejects_reused_code(self):
        code = self.authorize_code().data["code"]
        first = self.exchange_code(code)
        second = self.exchange_code(code)

        self.assertEqual(first.status_code, status.HTTP_200_OK)
        self.assertEqual(second.status_code, status.HTTP_400_BAD_REQUEST)

    def test_token_exchange_rejects_bad_pkce_verifier(self):
        code = self.authorize_code().data["code"]

        response = self.exchange_code(code, verifier="b" * 43)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(SSOAuthorizationCode.objects.get().is_used())


@override_settings(
    SSO_ALLOWED_REDIRECT_URIS=[],
    SSO_AUTH_CODE_LIFETIME_SECONDS=300,
)
class SSOBridgeDBRedirectTests(SSOBridgeTests):
    def setUp(self):
        super().setUp()
        self.allow_redirect_in_db()

    def test_authorize_code_uses_db_allowed_redirect_uri(self):
        response = self.authorize_code()

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(SSOAuthorizationCode.objects.count(), 1)

    def test_token_exchange_uses_db_allowed_redirect_uri(self):
        code = self.authorize_code().data["code"]

        response = self.exchange_code(code)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)


@override_settings(
    SSO_ALLOWED_REDIRECT_URIS=[],
    SSO_AUTH_CODE_LIFETIME_SECONDS=300,
)
class SSOBridgeInactiveDBRedirectTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="sso-user@example.com",
            password="testpassword",
            is_active=True,
        )
        self.authorize_url = reverse("sso_authorize_code")
        self.redirect_uri = "https://sales.ourlilstudio.com/auth/callback"
        self.client_id = "ols-mp"
        self.challenge = pkce_challenge("a" * 43)
        SSOAllowedRedirectURI.objects.create(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            is_active=False,
        )

    def test_authorize_code_rejects_inactive_db_redirect_uri(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            self.authorize_url,
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "code_challenge": self.challenge,
                "code_challenge_method": "S256",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(SSOAuthorizationCode.objects.count(), 0)
