"""Signed-JWT and database integration tests for tenant-bound CRM codes."""
import base64
import hashlib
import uuid
from unittest.mock import Mock, patch
import jwt
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from authentication.models import User, SSOAllowedRedirectURI, SSOAuthorizationCode
from authentication.serializers import MyTokenObtainPairSerializer
from authentication.sso_views import _issue_authorization_code, _browser_fingerprint
from organization.models import Organization, OrganizationMember
from iam.models import CRMTenantGrant


class BoundCRMCodeTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email="owner@example.test", password="test", is_active=True)
        self.user = User.objects.create_user(email="member@example.test", password="test", is_active=True)
        self.org = Organization.objects.create(name="Isolated", owner=self.owner, package_type="Basic")
        self.member = OrganizationMember.objects.create(user=self.user, organization=self.org, is_session_active=True)
        self.tenant = str(uuid.uuid4())
        self.other = str(uuid.uuid4())
        self.grant = CRMTenantGrant.objects.create(organization_member=self.member, tenant_id=self.tenant, permissions=["crm.manage"])
        self.callback = "https://client.test/crm/callback"
        SSOAllowedRedirectURI.objects.create(client_id="arna-site-crm", redirect_uri=self.callback, is_active=True)
        self.verifier = "a" * 43
        self.payload = {"client_id": "arna-site-crm", "redirect_uri": self.callback,
                        "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode(),
                        "code_challenge_method": "S256", "state": "csrf", "tenant_id": self.tenant}
        self.lookup = patch("authentication.crm_proof.requests.get")
        self.get = self.lookup.start()
        self.addCleanup(self.lookup.stop)
        self.get.return_value = Mock(status_code=200)
        self.get.return_value.json.return_value = {"results": [
            {"tenant_id": t, "sso_organization_id": str(self.org.pk), "is_active": True}
            for t in (self.tenant, self.other)
        ]}

    def authorize(self):
        token = MyTokenObtainPairSerializer.access_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        return self.client.post(reverse("sso_authorize_code"), self.payload, format="json")

    def code(self):
        result = self.authorize()
        self.assertEqual(result.status_code, 201, result.data)
        return result.data["code"]

    def exchange(self, code):
        self.client.credentials()
        return self.client.post(reverse("sso_token_exchange"), {
            "client_id": "arna-site-crm", "redirect_uri": self.callback, "code": code,
            "grant_type": "authorization_code", "code_verifier": self.verifier,
            "tenant_id": self.other, "tenant_ids": [self.other], "is_owner": True,
        }, format="json")

    def decode(self, result):
        return jwt.decode(result.data["access"], settings.SIMPLE_JWT["VERIFYING_KEY"], algorithms=["RS256"], audience="arna-crm")

    def test_signed_base_login_and_singleton_proof(self):
        result = self.exchange(self.code())
        self.assertEqual(result.status_code, 200, result.data)
        claims = self.decode(result)
        self.assertEqual(claims["tenant_ids"], [self.tenant])
        self.assertEqual(claims["tenant_id"], self.tenant)
        self.assertEqual(claims["permissions"], ["crm.manage"])
        self.assertFalse(claims["is_owner"])
        self.assertNotIn("user_id", claims)
        self.assertEqual(claims["crm_contract_version"], 1)
        self.assertLessEqual(claims["exp"] - claims["iat"], 60)

    def test_signed_crm_proof_cannot_authorize_generic_sso(self):
        proof = self.exchange(self.code()).data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {proof}")
        self.assertEqual(self.client.post(reverse("sso_authorize_code"), self.payload, format="json").status_code, 401)

    def test_generic_jwt_authentication_cannot_resolve_crm_user(self):
        proof = self.exchange(self.code()).data["access"]
        authentication = JWTAuthentication()
        validated = authentication.get_validated_token(proof.encode())
        with self.assertRaises(InvalidToken):
            authentication.get_user(validated)

    def test_revoke_after_authorization_denies_exchange(self):
        code = self.code()
        self.grant.is_active = False
        self.grant.save()
        self.assertEqual(self.exchange(code).status_code, 403)
        self.assertFalse(SSOAuthorizationCode.objects.get(code_hash=SSOAuthorizationCode.hash_code(code)).is_used())

    def test_selector_change_denies_exchange(self):
        code = self.code()
        self.member.active_tenant_id = self.other
        self.member.save()
        self.assertEqual(self.exchange(code).status_code, 403)

    def test_membership_switch_denies_exchange(self):
        code = self.code()
        self.member.is_session_active = False
        self.member.save()
        self.assertEqual(self.exchange(code).status_code, 403)

    def test_owner_change_denies_exchange(self):
        code = self.code()
        self.org.owner = self.user
        self.org.save()
        self.assertEqual(self.exchange(code).status_code, 403)

    def test_inactive_directory_tenant_denies_exchange(self):
        code = self.code()
        self.get.return_value.json.return_value["results"][0]["is_active"] = False
        self.assertEqual(self.exchange(code).status_code, 403)

    def test_code_is_single_use(self):
        code = self.code()
        self.assertEqual(self.exchange(code).status_code, 200)
        self.assertEqual(self.exchange(code).status_code, 400)

    def test_legacy_unbound_code_is_denied(self):
        code = self.code()
        SSOAuthorizationCode.objects.filter(code_hash=SSOAuthorizationCode.hash_code(code)).update(crm_context={})
        self.assertEqual(self.exchange(code).status_code, 403)

    def test_original_credential_expiry_caps_proof(self):
        code = self.code()
        expiry = int(timezone.now().timestamp()) + 12
        SSOAuthorizationCode.objects.filter(code_hash=SSOAuthorizationCode.hash_code(code)).update(credential_expires_at=expiry)
        claims = self.decode(self.exchange(code))
        self.assertLessEqual(claims["exp"], expiry)

    def test_expired_original_credential_denies_exchange(self):
        code = self.code()
        SSOAuthorizationCode.objects.filter(code_hash=SSOAuthorizationCode.hash_code(code)).update(credential_expires_at=int(timezone.now().timestamp())-1)
        self.assertEqual(self.exchange(code).status_code, 403)

    def test_logout_invalidates_browser_bound_code(self):
        store = SessionStore()
        store["browser_user"] = str(self.user.pk)
        store["auth_fingerprint"] = _browser_fingerprint(self.user)
        store.set_expiry(120)
        store.create()
        result = _issue_authorization_code(self.user, self.payload, browser_session_key=store.session_key)
        store.delete()
        self.assertEqual(self.exchange(result.data["code"]).status_code, 403)

    def test_permission_change_after_authorization_denies_exchange(self):
        code = self.code()
        self.grant.permissions = ["crm.read"]
        self.grant.save()
        self.assertEqual(self.exchange(code).status_code, 403)

    def test_delete_and_recreate_grant_denies_pending_code(self):
        code = self.code()
        self.grant.delete()
        CRMTenantGrant.objects.create(organization_member=self.member, tenant_id=self.tenant, permissions=["crm.manage"])
        self.assertEqual(self.exchange(code).status_code, 403)
