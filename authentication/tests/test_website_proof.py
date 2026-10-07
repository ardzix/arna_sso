import base64
import hashlib

import jwt
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from authentication.models import SSOAllowedRedirectURI, SSOAuthorizationCode, User


@override_settings(SSO_ALLOWED_REDIRECT_URIS=[], SSO_AUTH_CODE_LIFETIME_SECONDS=300)
class WebsiteProofTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="website-proof@example.test", password=None, is_active=True,
            phone_number="628123456789", phone_verified=True,
        )
        self.client_id = "arna-site-website"
        self.redirect = "https://127.0.0.1:3000/api/v1/website/customer/callback"
        self.verifier = "v" * 43
        self.challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.verifier.encode()).digest()
        ).rstrip(b"=").decode()
        SSOAllowedRedirectURI.objects.create(client_id=self.client_id, redirect_uri=self.redirect)

    def authorize(self, **overrides):
        self.client.force_authenticate(user=self.user)
        return self.client.post(reverse("sso_authorize_code"), {
            "client_id": self.client_id, "redirect_uri": self.redirect,
            "code_challenge": self.challenge, "code_challenge_method": "S256",
            **overrides,
        }, format="json")

    def exchange(self, code, **overrides):
        self.client.force_authenticate(user=None)
        return self.client.post(reverse("sso_token_exchange"), {
            "grant_type": "authorization_code", "client_id": self.client_id,
            "redirect_uri": self.redirect, "code": code, "code_verifier": self.verifier,
            **overrides,
        }, format="json")

    def test_proof_has_signed_phone_and_target_claims_without_dashboard_rights(self):
        response = self.exchange(self.authorize().data["code"])
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("refresh", response.data)
        issuer = settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id"
        audience = settings.SIMPLE_JWT.get("AUDIENCE") or "arna-site-website"
        claims = jwt.decode(response.data["access"], settings.SIMPLE_JWT["VERIFYING_KEY"],
                            algorithms=["RS256"], issuer=issuer, audience=audience)
        self.assertEqual(claims["sub"], str(self.user.pk))
        self.assertEqual(claims["phone_number"], self.user.phone_number)
        self.assertIs(claims["phone_verified"], True)
        self.assertEqual(claims["scope"], "website.customer")
        self.assertEqual(claims["token_type"], "website_customer")
        self.assertEqual(claims["exp"] - claims["iat"], 1800)
        for name in ("permissions", "org_id", "tenant_ids", "is_owner"):
            self.assertNotIn(name, claims)
        for token_class in (AccessToken, RefreshToken):
            with self.assertRaises(TokenError):
                token_class(response.data["access"])

    def test_unverified_phone_and_plain_pkce_never_issue_website_code(self):
        self.assertEqual(self.authorize(code_challenge_method="plain").status_code, 400)
        self.user.phone_verified = False
        self.user.save(update_fields=["phone_verified"])
        self.assertEqual(self.authorize().status_code, 403)
        self.assertEqual(SSOAuthorizationCode.objects.count(), 0)

    def test_phone_revocation_before_exchange_is_rejected(self):
        code = self.authorize().data["code"]
        self.user.phone_verified = False
        self.user.save(update_fields=["phone_verified"])
        self.assertEqual(self.exchange(code).status_code, 403)
        self.assertIsNone(SSOAuthorizationCode.objects.get().used_at)

    def test_bad_verifier_changed_client_expiry_and_reuse_are_rejected(self):
        code = self.authorize().data["code"]
        self.assertEqual(self.exchange(code, code_verifier="x" * 43).status_code, 400)
        self.assertEqual(self.exchange(code, client_id="other-client").status_code, 400)
        self.assertEqual(self.exchange(code).status_code, 200)
        self.assertEqual(self.exchange(code).status_code, 400)
        another = self.authorize().data["code"]
        from django.utils import timezone
        SSOAuthorizationCode.objects.filter(used_at__isnull=True).update(
            expires_at=timezone.now() - timezone.timedelta(seconds=1)
        )
        self.assertEqual(self.exchange(another).status_code, 400)

    def test_other_client_keeps_existing_access_and_refresh_contract(self):
        self.client_id = "existing-product"
        SSOAllowedRedirectURI.objects.create(client_id=self.client_id, redirect_uri=self.redirect)
        response = self.exchange(self.authorize().data["code"])
        self.assertEqual(response.status_code, 200)
        self.assertIn("refresh", response.data)
        self.assertEqual(AccessToken(response.data["access"])["token_type"], "access")
        self.assertEqual(RefreshToken(response.data["refresh"])["token_type"], "refresh")
