import hashlib
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from django.contrib.sessions.backends.db import SessionStore
from django.test import Client, TestCase
from django.utils import timezone
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import SSOAllowedRedirectURI, SSOAppSession, SSOAuthorizationCode, User
from authentication.serializers import MyTokenObtainPairSerializer
from authentication.sso_views import SSO_BROWSER_COOKIE, _challenge_from_verifier


class AppSessionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("app-session@example.test", "synthetic-password", is_active=True)
        self.browser = Client(enforce_csrf_checks=True)
        self.params = dict(client_id="arna-account", redirect_uri="https://account.arnatech.id/api/auth/callback",
                           code_challenge=_challenge_from_verifier("v"*64, "S256"), code_challenge_method="S256", state="test-state")
        self.browser.get("/login/")
        token = MyTokenObtainPairSerializer.get_token(self.user).access_token
        self.assertEqual(self.browser.post("/login/session/", {}, content_type="application/json",
            HTTP_AUTHORIZATION="Bearer "+str(token), HTTP_X_CSRFTOKEN=self.browser.cookies["csrftoken"].value,
            HTTP_ORIGIN="https://sso.arnatech.id").status_code, 200)
        self.backend = Client()

    def code(self, params=None):
        params = params or self.params
        SSOAllowedRedirectURI.objects.get_or_create(client_id=params["client_id"], redirect_uri=params["redirect_uri"])
        response = self.browser.get("/login/", params)
        self.assertEqual(response.status_code, 302)
        code = parse_qs(urlsplit(response["Location"]).query)["code"][0]
        return dict(grant_type="authorization_code", client_id=params["client_id"], redirect_uri=params["redirect_uri"],
                    code=code, code_verifier="v"*64)

    def create(self, data=None):
        return self.backend.post("/api/auth/sso/app-session/", data or self.code(), content_type="application/json")

    def resolve(self, credential, client_id="arna-account"):
        return self.backend.post("/api/auth/sso/app-session/resolve/", {"client_id": client_id},
            content_type="application/json", HTTP_AUTHORIZATION="Bearer "+credential)

    def test_once_only_bound_code_and_hashed_opaque_session(self):
        data = self.code()
        response = self.create(data)
        self.assertEqual(response.status_code, 201)
        raw = response.json()["session"]
        self.assertEqual(len(raw), 64)
        self.assertNotIn("access", response.json())
        self.assertNotIn("refresh", response.json())
        self.assertTrue(SSOAppSession.objects.filter(credential_hash=hashlib.sha256(raw.encode()).hexdigest()).exists())
        self.assertEqual(self.create(data).status_code, 400)
        self.assertEqual(self.resolve(raw).status_code, 200)
        self.assertEqual(self.resolve(raw, "arnaos").status_code, 401)
        with patch.object(MyTokenObtainPairSerializer, "get_token", side_effect=AssertionError("Refresh issuance is forbidden")):
            self.assertNotIn("refresh", self.resolve(raw).json())

    def test_wrong_verifier_callback_or_unbound_legacy_code_is_rejected(self):
        for key, value in (("code_verifier", "w"*64), ("redirect_uri", "https://evil.test/callback"), ("client_id", "arnaos")):
            data = self.code()
            data[key] = value
            self.assertEqual(self.create(data).status_code, 400)
        data = self.code()
        SSOAuthorizationCode.objects.filter(code_hash=SSOAuthorizationCode.hash_code(data["code"])).update(browser_session_key="")
        self.assertEqual(self.create(data).status_code, 401)

    def test_local_logout_does_not_end_other_app_and_central_logout_ends_both(self):
        account = self.create().json()["session"]
        company = self.create(self.code({**self.params, "client_id": "arnaos", "redirect_uri": "https://company.arnatech.id/api/auth/callback"})).json()["session"]
        revoke = self.backend.post("/api/auth/sso/app-session/revoke/", {"client_id": "arna-account"},
            content_type="application/json", HTTP_AUTHORIZATION="Bearer "+account)
        self.assertEqual(revoke.status_code, 200)
        self.assertEqual(self.resolve(account).status_code, 401)
        self.assertEqual(self.resolve(company, "arnaos").status_code, 200)
        claims = AccessToken(self.resolve(company, "arnaos").json()["access"])
        self.assertEqual(claims["aud"], "arnaos")
        self.assertEqual(claims["iss"], "https://sso.arnatech.id")
        self.browser.post("/login/logout/", {"csrfmiddlewaretoken": self.browser.cookies["csrftoken"].value},
                          HTTP_ORIGIN="https://sso.arnatech.id")
        self.assertEqual(self.resolve(company, "arnaos").status_code, 401)

    def test_explicit_all_app_logout_revokes_the_source_session(self):
        first = self.create().json()["session"]
        second = self.create().json()["session"]
        response = self.backend.post("/api/auth/sso/app-session/revoke/", {"client_id": "arna-account", "all": True},
            content_type="application/json", HTTP_AUTHORIZATION="Bearer " + first)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.resolve(first).status_code, 401)
        self.assertEqual(self.resolve(second).status_code, 401)
        self.assertContains(self.browser.get("/login/"), 'id="passwordForm"')
        self.assertEqual(self.backend.post("/api/auth/sso/app-session/revoke/", {"client_id": "arna-account", "all": True},
            content_type="application/json", HTTP_AUTHORIZATION="Bearer " + first).status_code, 401)

    def test_expiry_disabled_user_password_change_and_mfa_change_invalidate(self):
        raw = self.create().json()["session"]
        self.user.set_password("new-synthetic-password")
        self.user.save(update_fields=["password"])
        self.assertEqual(self.resolve(raw).status_code, 401)
        for field, value in (("mfa_secret", "JBSWY3DPEHPK3PXP"), ("is_active", False)):
            self.user.refresh_from_db()
            store = SessionStore(session_key=self.browser.cookies[SSO_BROWSER_COOKIE].value)
            from authentication.sso_views import _browser_fingerprint
            store["auth_fingerprint"] = _browser_fingerprint(self.user)
            store.save()
            setattr(self.user, field, value)
            self.user.save(update_fields=[field])
            self.assertEqual(self.resolve(raw).status_code, 401)
        SSOAppSession.objects.update(expires_at=timezone.now())
        self.assertEqual(self.resolve(raw).status_code, 401)

    def test_fresh_login_with_pkce_binds_code_before_returning(self):
        self.browser.cookies.clear()
        self.browser.get("/login/", self.params)
        token = MyTokenObtainPairSerializer.get_token(self.user).access_token
        response = self.browser.post("/login/session/", self.params, content_type="application/json",
            HTTP_AUTHORIZATION="Bearer "+str(token), HTTP_X_CSRFTOKEN=self.browser.cookies["csrftoken"].value,
            HTTP_ORIGIN="https://sso.arnatech.id")
        self.assertEqual(response.status_code, 200)
        code = parse_qs(urlsplit(response.json()["redirect_url"]).query)["code"][0]
        data = dict(grant_type="authorization_code", client_id=self.params["client_id"], redirect_uri=self.params["redirect_uri"], code=code, code_verifier="v"*64)
        self.assertEqual(self.create(data).status_code, 201)
