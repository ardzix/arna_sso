import base64
import hashlib
import uuid
from unittest.mock import Mock, patch

import jwt
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from authentication.models import User, SSOAllowedRedirectURI, SSOAuthorizationCode
from organization.models import Organization, OrganizationMember


@override_settings(SSO_ALLOWED_REDIRECT_URIS=[], CRM_ARNASITE_TENANTS_URL="https://site.test/api/tenants/")
class CrmDashboardTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email="crm-dashboard@example.com", password="test-password", is_active=True)
        self.org = Organization.objects.create(name="Pilot", owner=self.user, package_type="Basic")
        self.member = OrganizationMember.objects.create(user=self.user, organization=self.org, is_session_active=True)
        self.tenant = str(uuid.uuid4())
        self.callback = "https://dashboard.test/api/crm/auth/callback"
        SSOAllowedRedirectURI.objects.create(client_id="arna-site-crm", redirect_uri=self.callback, is_active=True)
        self.verifier = "a" * 43
        self.challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        self.payload = {"client_id": "arna-site-crm", "redirect_uri": self.callback,
                        "code_challenge": self.challenge, "code_challenge_method": "S256", "state": "csrf-state"}

    def grant(self, **kwargs):
        self.client.force_authenticate(user=self.user)
        return self.client.post(reverse("sso_authorize_code"), {**self.payload, **kwargs}, format="json")

    def exchange(self, code):
        self.client.force_authenticate(user=None)
        return self.client.post(reverse("sso_token_exchange"), {
            "client_id": "arna-site-crm", "redirect_uri": self.callback, "code": code,
            "grant_type": "authorization_code", "code_verifier": self.verifier,
            "tenant_ids": [str(uuid.uuid4())], "is_owner": True, "scope": "crm.manage",
        }, format="json")

    def rows(self, **kwargs):
        return {"count": 1, "results": [{"tenant_id": self.tenant,
                 "sso_organization_id": str(self.org.pk), "is_active": True, **kwargs}]}

    @patch("authentication.crm_proof.requests.get")
    def test_dashboard_issues_audience_tenant_bound_access_only_and_consumes_once(self, get):
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = self.rows()
        code = self.grant().data["code"]
        response = self.exchange(code)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("refresh", response.data)
        claims = jwt.decode(response.data["access"], settings.SIMPLE_JWT["VERIFYING_KEY"],
                            algorithms=["RS256"], audience="arna-crm", issuer=settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id")
        self.assertEqual(claims["sub"], str(self.user.pk))
        self.assertEqual(claims["organization_id"], str(self.org.pk))
        self.assertEqual(claims["tenant_ids"], [self.tenant])
        self.assertTrue(claims["is_owner"])
        self.assertEqual(claims["token_type"], "access")
        self.assertEqual(self.exchange(code).status_code, 400)
        self.assertEqual(get.call_count, 1)
        _, kwargs = get.call_args
        self.assertEqual(kwargs["timeout"], 8)
        self.assertFalse(kwargs["allow_redirects"])

    def test_plain_pkce_and_unregistered_redirect_are_rejected(self):
        self.assertEqual(self.grant(code_challenge_method="plain").status_code, 400)
        SSOAllowedRedirectURI.objects.all().delete()
        with override_settings(SSO_ALLOWED_REDIRECT_URIS=[self.callback]):
            self.assertEqual(self.grant().status_code, 400)
        self.assertEqual(SSOAuthorizationCode.objects.count(), 0)

    @patch("authentication.crm_proof.requests.get")
    def test_other_org_invalid_uuid_and_inactive_tenants_cannot_grant_access(self, get):
        for row, expected in [(self.rows(sso_organization_id=str(uuid.uuid4())), 503),
                              (self.rows(tenant_id="legacy-db-id"), 503), (self.rows(is_active=False), 403)]:
            get.return_value = Mock(status_code=200)
            get.return_value.json.return_value = row
            code = self.grant().data["code"]
            self.assertEqual(self.exchange(code).status_code, expected)
            self.assertFalse(SSOAuthorizationCode.objects.get(code_hash=SSOAuthorizationCode.hash_code(code)).is_used())

    @patch("authentication.crm_proof.requests.get")
    def test_no_active_membership_does_not_contact_site(self, get):
        code = self.grant().data["code"]
        self.member.is_session_active = False
        self.member.save()
        self.assertEqual(self.exchange(code).status_code, 403)
        get.assert_not_called()

    @patch("authentication.crm_proof.requests.get")
    def test_site_failures_and_redirects_do_not_consume_code(self, get):
        for upstream in [503, 302, 401]:
            get.return_value = Mock(status_code=upstream)
            code = self.grant().data["code"]
            self.assertEqual(self.exchange(code).status_code, 503)
            self.assertFalse(SSOAuthorizationCode.objects.get(code_hash=SSOAuthorizationCode.hash_code(code)).is_used())

    @patch("authentication.crm_proof.requests.get")
    def test_membership_change_during_site_lookup_blocks_grant(self, get):
        def lookup(*args, **kwargs):
            OrganizationMember.objects.filter(pk=self.member.pk).update(is_session_active=False)
            response = Mock(status_code=200)
            response.json.return_value = self.rows()
            return response
        get.side_effect = lookup
        code = self.grant().data["code"]
        self.assertEqual(self.exchange(code).status_code, 403)

    @patch("authentication.crm_proof.requests.get")
    def test_member_cannot_inherit_owner_or_browser_submitted_manage_scope(self, get):
        other = User.objects.create_user(email="real-owner@example.com", password=None, is_active=True)
        self.org.owner = other
        self.org.save()
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = self.rows()
        response = self.exchange(self.grant().data["code"])
        self.assertEqual(response.status_code, 200)
        claims = jwt.decode(response.data["access"], settings.SIMPLE_JWT["VERIFYING_KEY"], algorithms=["RS256"], audience="arna-crm")
        self.assertFalse(claims["is_owner"])
        self.assertEqual(claims["permissions"], [])
        self.assertNotIn("scope", claims)

    @patch("authentication.crm_proof.requests.get")
    def test_insecure_directory_url_is_rejected(self, get):
        code = self.grant().data["code"]
        with override_settings(DEBUG=False, CRM_ARNASITE_TENANTS_URL="http://site.test/api/tenants/"):
            self.assertEqual(self.exchange(code).status_code, 503)
        get.assert_not_called()
