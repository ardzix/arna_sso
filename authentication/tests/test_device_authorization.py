import base64
import hashlib
import time
import uuid
import importlib
from datetime import timedelta
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from django.test import TransactionTestCase
from django.apps import apps
from django.db import connection, connections, close_old_connections
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient

from authentication.models import DeviceAuthorizationGrant, DeviceRegistration, DeviceRefreshCredential, ServiceAccount, User
from iam.models import Permission, Role, UserRole, UserPermission
from organization.models import Organization, OrganizationMember


BASE = "/api/v1/devices/"


@override_settings(DEVICE_ALLOWED_AUDIENCES=["photobooth-api"], DEVICE_AUDIENCE_SCOPES={"photobooth-api": ["photobooth.session", "photobooth.session.write"]})
class DeviceAuthorizationTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.owner = User.objects.create_user(email="device-owner@example.test", password="synthetic", is_active=True)
        self.other = User.objects.create_user(email="device-other@example.test", password="synthetic", is_active=True)
        self.org = Organization.objects.create(name="Device A", owner=self.owner, package_type="Basic")
        self.org_b = Organization.objects.create(name="Device B", owner=self.other, package_type="Basic")
        self.tenant = str(uuid.uuid4())
        self.tenant_b = str(uuid.uuid4())
        self.owner_member = OrganizationMember.objects.create(user=self.owner, organization=self.org, active_tenant_id=self.tenant)
        self.other_member = OrganizationMember.objects.create(user=self.other, organization=self.org_b, active_tenant_id=self.tenant_b)
        self.lookup = patch("authentication.device_security.requests.get", side_effect=self.tenant_response).start()
        self.addCleanup(patch.stopall)

    def tenant_response(self, url, headers, **kwargs):
        token = jwt.decode(headers["Authorization"].split()[1], settings.SIMPLE_JWT["VERIFYING_KEY"],
                           algorithms=["RS256"], audience="arna-site", issuer="https://sso.arnatech.id")
        self.assertEqual(token["permissions"], [])
        self.assertEqual(kwargs, {"timeout": 8, "allow_redirects": False})
        tenant = self.tenant if token["org_id"] == str(self.org.pk) else self.tenant_b
        return Mock(status_code=200, json=Mock(return_value={"results": [
            {"tenant_id": tenant, "sso_organization_id": token["org_id"], "is_active": True}]}))

    def authorize(self, headers=None, **extra):
        return self.client.post(BASE + "authorize/", {
            "client_id": "synthetic-device", "device_name": "Test kiosk", "tenant_id": self.tenant,
            "organization_id": str(self.org.pk), "audience": "photobooth-api", "scopes": ["photobooth.session"], **extra,
        }, format="json", **(headers or {}))

    def decision(self, grant, owner=None, org=None, action="approve"):
        self.client.force_authenticate(user=owner or self.owner)
        return self.client.post(BASE + "verification/", {"user_code": grant["user_code"],
                                "organization_id": str((org or self.org).pk), "action": action}, format="json")

    def token(self, grant, headers=None):
        return self.client.post(BASE + "token/", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                "device_code": grant["device_code"]}, format="json", **(headers or {}))

    def pair(self, **extra):
        grant = self.authorize(**extra)
        self.assertEqual(grant.status_code, 201, grant.data)
        self.assertEqual(self.decision(grant.data).status_code, 200)
        pair = self.token(grant.data)
        self.assertEqual(pair.status_code, 200, pair.data)
        return pair.data

    def refresh(self, pair, headers=None):
        return self.client.post(BASE + "refresh/", {"refresh_token": pair["refresh_token"]}, format="json", **(headers or {}))

    def status(self, pair, headers=None):
        self.client.force_authenticate(user=None)
        return self.client.get(BASE + "status/", HTTP_AUTHORIZATION="Bearer " + pair["access_token"], **(headers or {}))

    def test_end_to_end_claims_identity_rotation_and_revocation(self):
        grant = self.authorize().data
        first = self.token(grant)
        self.assertEqual(first.data["error"], "authorization_pending")
        self.assertTrue(first.data["detail"])
        self.assertTrue(first.data["request_id"])
        slow = self.token(grant)
        self.assertEqual(slow.data["error"], "slow_down")
        self.assertEqual(slow.data["interval"], 10)
        self.assertEqual(self.decision(grant).status_code, 200)
        DeviceAuthorizationGrant.objects.update(last_polled_at=timezone.now() - timedelta(minutes=1))
        pair = self.token(grant).data
        claims = jwt.decode(pair["access_token"], settings.SIMPLE_JWT["VERIFYING_KEY"], algorithms=["RS256"],
                            issuer=settings.DEVICE_TOKEN_ISSUER, audience="photobooth-api")
        self.assertEqual(claims["token_type"], "device")
        self.assertEqual(claims["sub"], pair["device_id"])
        self.assertEqual(claims["organization_id"], str(self.org.pk))
        self.assertEqual(claims["tenant_id"], self.tenant)
        self.assertEqual(claims["exp"] - claims["iat"], 300)
        self.assertNotIn("user_id", claims)
        self.assertEqual(self.status(pair).status_code, 200)
        self.assertEqual(self.token(grant).data["error"], "invalid_grant")
        rotated = self.refresh(pair)
        self.assertEqual(rotated.status_code, 200)
        self.assertNotEqual(pair["refresh_token"], rotated.data["refresh_token"])
        self.assertEqual(self.refresh(pair).status_code, 400)
        self.client.force_authenticate(user=self.owner)
        self.assertEqual(self.client.post(BASE + "revoke/", {"device_id": pair["device_id"]}, format="json").status_code, 204)
        self.assertEqual(self.refresh(rotated.data).status_code, 400)
        self.assertEqual(self.status(pair).status_code, 401)

    def test_invalid_fields_are_400_on_both_route_versions(self):
        grant = self.authorize().data
        self.client.force_authenticate(user=self.owner)
        for base in (BASE, "/api/auth/device/"):
            for path, payload in (("verification/", {"user_code": grant["user_code"], "organization_id": "not-uuid"}),
                                  ("revoke/", {"device_id": "not-uuid"}),
                                  ("review/", {"user_code": grant["user_code"], "organization_id": []})):
                response = self.client.post(base + path, payload, format="json")
                self.assertEqual(response.status_code, 400, response.data)
                self.assertEqual(response.data["error"], "invalid_request")
                self.assertIn("request_id", response.data)
        self.assertEqual(self.authorize(client_id="x" * 121).status_code, 400)
        self.assertEqual(self.authorize(tenant_id="bad").status_code, 400)
        self.assertEqual(self.authorize(organization_id="bad").status_code, 400)
        self.assertEqual(self.authorize(scopes="not-a-list").status_code, 400)
        for path in ("authorize/", "review/", "verification/", "token/", "refresh/", "revoke/"):
            response = self.client.post(BASE + path, ["malformed"], format="json")
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("ErrorDetail", response.data["detail"])

    def test_scope_and_audience_policy_blocks_backend_privileges(self):
        for extra in ({"audience": "photobooth"}, {"scopes": ["commerce.checkout.create"]},
                      {"scopes": ["photobooth.session", "unknown.scope"]}, {"scopes": []}):
            self.assertEqual(self.authorize(**extra).status_code, 400)
        self.assertEqual(DeviceAuthorizationGrant.objects.count(), 0)
        self.assertEqual(self.authorize(scopes=["photobooth.session.write"]).status_code, 201)

    def test_requested_organization_cannot_be_changed_by_operator(self):
        grant = self.authorize().data
        self.assertEqual(self.decision(grant, owner=self.other, org=self.org_b).status_code, 403)
        self.lookup.assert_not_called()
        self.assertEqual(DeviceRegistration.objects.count(), 0)

    def test_review_shows_only_public_details_and_checks_permission(self):
        grant = self.authorize().data
        self.client.force_authenticate(user=self.other)
        payload = {"user_code": grant["user_code"], "organization_id": str(self.org.pk)}
        self.assertEqual(self.client.post(BASE + "review/", payload, format="json").status_code, 403)
        self.lookup.assert_not_called()
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(BASE + "review/", payload, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["tenant_id"], self.tenant)
        self.assertEqual(response.data["scopes"], ["photobooth.session"])
        for key in ("device_code", "refresh_token", "access_token", "device_code_hash"):
            self.assertNotIn(key, response.data)
        self.assertFalse(DeviceRegistration.objects.exists())

    def test_wrong_or_inactive_tenant_is_rejected(self):
        grant = self.authorize(tenant_id=str(uuid.uuid4())).data
        self.assertEqual(self.decision(grant).status_code, 403)
        self.lookup.side_effect = None
        self.lookup.return_value = Mock(status_code=200, json=Mock(return_value={"results": [
            {"tenant_id": self.tenant, "sso_organization_id": str(self.org.pk), "is_active": False}]}))
        self.assertEqual(self.decision(self.authorize().data).status_code, 403)
        self.assertEqual(DeviceRegistration.objects.count(), 0)

    def test_dependency_timeout_and_untrusted_response_fail_closed(self):
        grant = self.authorize().data
        for error in (requests.Timeout(), Mock(status_code=302),
                      Mock(status_code=200, json=Mock(return_value={"results": [], "next": "https://other.test"})),
                      Mock(status_code=200, json=Mock(return_value={"results": [{"tenant_id": self.tenant,
                                                        "sso_organization_id": str(self.org_b.pk), "is_active": True}]}))):
            self.lookup.side_effect = error if isinstance(error, Exception) else None
            self.lookup.return_value = error
            self.assertEqual(self.decision(grant).status_code, 503)
        self.assertFalse(DeviceRegistration.objects.exists())

    def test_approve_checks_owner_again_after_review(self):
        grant = self.authorize().data
        self.org.owner = self.other
        self.org.save()
        self.assertEqual(self.decision(grant).status_code, 403)

    def test_denied_expired_and_duplicate_decisions_do_not_pair(self):
        grant = self.authorize().data
        self.assertEqual(self.decision(grant, action="deny").status_code, 200)
        self.assertEqual(self.token(grant).data["error"], "access_denied")
        self.assertEqual(self.decision(grant).status_code, 400)
        grant = self.authorize().data
        DeviceAuthorizationGrant.objects.filter(denied_at__isnull=True).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.token(grant).data["error"], "expired_token")
        self.assertEqual(self.decision(grant).status_code, 400)
        grant = self.authorize().data
        self.assertEqual(self.decision(grant).status_code, 200)
        self.assertEqual(self.decision(grant).status_code, 400)

    def test_pairing_same_tenant_invalidates_old_refresh_and_access(self):
        first = self.pair()
        second = self.pair()
        self.assertEqual(first["device_id"], second["device_id"])
        self.assertGreater(second["credential_version"], first["credential_version"])
        self.assertEqual(self.refresh(first).status_code, 400)
        self.assertEqual(self.status(first).status_code, 401)
        self.assertEqual(self.status(second).status_code, 200)

    def test_unconsumed_approved_grant_cannot_follow_new_assignment(self):
        grant = self.authorize().data
        self.assertEqual(self.decision(grant).status_code, 200)
        self.pair()
        self.assertEqual(self.token(grant).data["error"], "access_denied")

    def test_cross_org_reassignment_requires_revoke_and_new_approval(self):
        first = self.pair()
        grant = self.authorize(organization_id=str(self.org_b.pk), tenant_id=self.tenant_b).data
        self.assertEqual(self.decision(grant, owner=self.other, org=self.org_b).status_code, 409)
        self.client.force_authenticate(user=self.other)
        self.assertEqual(self.client.post(BASE + "revoke/", {"device_id": first["device_id"]}, format="json").status_code, 403)
        self.client.force_authenticate(user=self.owner)
        self.assertEqual(self.client.post(BASE + "revoke/", {"device_id": first["device_id"]}, format="json").status_code, 204)
        self.assertEqual(self.decision(grant, owner=self.other, org=self.org_b).status_code, 200)
        second = self.token(grant).data
        self.assertEqual(second["organization_id"], str(self.org_b.pk))
        self.assertEqual(second["tenant_id"], self.tenant_b)
        self.assertEqual(self.refresh(first).status_code, 400)

    def test_inventory_and_detail_are_organization_tenant_scoped_paginated(self):
        pair = self.pair()
        self.client.force_authenticate(user=self.other)
        self.assertEqual(self.client.get(BASE + "registrations/", {"organization_id": str(self.org.pk)}).status_code, 403)
        response = self.client.get(BASE + "registrations/", {"organization_id": str(self.org_b.pk)})
        self.assertEqual(response.data["count"], 0)
        self.assertEqual(self.client.get(BASE + "registrations/" + pair["device_id"] + "/",
                                        {"organization_id": str(self.org_b.pk)}).status_code, 404)
        self.client.force_authenticate(user=self.owner)
        self.assertEqual(self.client.get(BASE + "registrations/", {"organization_id": str(self.org.pk), "tenant_id": self.tenant_b}).data["count"], 0)
        response = self.client.get(BASE + "registrations/", {"organization_id": str(self.org.pk), "page_size": 1})
        self.assertEqual(response.data["results"][0]["device_id"], pair["device_id"])
        self.assertEqual(self.client.get(BASE + "registrations/", {"organization_id": str(self.org.pk), "page_size": 1000}).status_code, 400)

    def test_permission_role_must_belong_to_same_organization(self):
        member = OrganizationMember.objects.create(user=self.other, organization=self.org, is_session_active=False, active_tenant_id=self.tenant)
        foreign = Permission.objects.create(organization=self.org_b, name="device.activate")
        role = Role.objects.create(name="Foreign device admin", organization=self.org_b)
        role.permissions.add(foreign)
        UserRole.objects.create(organization_member=member, role=role)
        direct = UserPermission.objects.create(organization_member=member)
        direct.permissions.add(foreign)
        grant = self.authorize().data
        self.assertEqual(self.decision(grant, owner=self.other).status_code, 403)
        own = Permission.objects.create(organization=self.org, name="device.activate")
        direct.permissions.add(own)
        self.other_member.is_session_active = False
        self.other_member.save(update_fields=['is_session_active'])
        member.is_session_active = True
        member.save(update_fields=['is_session_active'])
        self.assertEqual(self.decision(grant, owner=self.other).status_code, 200)

    def test_changed_scope_policy_revokes_refresh_and_status(self):
        pair = self.pair()
        with override_settings(DEVICE_AUDIENCE_SCOPES={"photobooth-api": ["other.scope"]}):
            self.assertEqual(self.refresh(pair).status_code, 400)
            self.assertEqual(self.status(pair).status_code, 401)

    def proof(self, path, key=None, **extra):
        key = key or self.key
        # Older PyJWT serializers drop leading zeroes, producing invalid P-256
        # JWK coordinates. RFC 7518 requires the full 32-byte representation.
        numbers = key.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256",
               "x": base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big")).rstrip(b"=").decode(),
               "y": base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big")).rstrip(b"=").decode()}
        return jwt.encode({"htm": "POST", "htu": settings.DEVICE_PUBLIC_ORIGIN + BASE + path,
                           "iat": int(time.time()), "jti": str(uuid.uuid4()), **extra}, key, algorithm="ES256",
                          headers={"typ": "dpop+jwt", "jwk": jwk})

    def bound_pair(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        response = self.authorize(headers={"HTTP_DPOP": self.proof("authorize/")})
        self.assertEqual(response.status_code, 201, response.data)
        grant = response.data
        self.assertEqual(self.decision(grant).status_code, 200)
        response = self.token(grant, {"HTTP_DPOP": self.proof("token/")})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["token_type"], "DPoP")
        return response.data

    def test_bare_thumbprint_does_not_claim_proof_of_possession(self):
        self.assertEqual(self.authorize(public_key_thumbprint="a" * 43).status_code, 400)
        self.assertFalse(DeviceAuthorizationGrant.objects.exists())

    def test_dpop_accepts_fixed_width_coordinates_with_leading_zero(self):
        # Deliberately public, synthetic test key; never used outside this test.
        self.key = ec.derive_private_key(43, ec.SECP256R1())
        self.assertEqual(self.authorize(headers={"HTTP_DPOP": self.proof("authorize/")}).status_code, 201)

    def test_dpop_key_binding_rejects_wrong_key_and_requires_fresh_proofs(self):
        pair = self.bound_pair()
        self.assertEqual(self.refresh(pair).status_code, 400)
        wrong = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(self.refresh(pair, {"HTTP_DPOP": self.proof("refresh/", key=wrong)}).status_code, 400)
        proof = self.proof("refresh/")
        rotated = self.refresh(pair, {"HTTP_DPOP": proof})
        self.assertEqual(rotated.status_code, 200)
        self.assertEqual(self.refresh(rotated.data, {"HTTP_DPOP": proof}).status_code, 400)
        self.assertEqual(self.refresh(rotated.data, {"HTTP_DPOP": self.proof("refresh/")}).status_code, 200)

    def test_dpop_bad_url_method_timestamp_and_algorithm_rejected(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        for extra in ({"htm": "GET"}, {"htu": "https://attacker.test/"}, {"iat": int(time.time()) - 500},
                      {"iat": int(time.time()) + 300}, {"jti": ""}):
            self.assertEqual(self.authorize(headers={"HTTP_DPOP": self.proof("authorize/", **extra)}).status_code, 400)
        self.assertEqual(self.authorize(headers={"HTTP_DPOP": "invalid-jwt"}).status_code, 400)

    def test_bound_status_requires_token_hash_and_registered_key(self):
        pair = self.bound_pair()
        self.client.force_authenticate(user=None)
        self.assertEqual(self.status(pair).status_code, 401)
        proof = self.proof("status/", htm="GET", ath="wrong")
        headers = {"HTTP_AUTHORIZATION": "DPoP " + pair["access_token"], "HTTP_DPOP": proof}
        self.assertEqual(self.client.get(BASE + "status/", **headers).status_code, 400)
        ath = base64.urlsafe_b64encode(hashlib.sha256(pair["access_token"].encode()).digest()).rstrip(b"=").decode()
        headers["HTTP_DPOP"] = self.proof("status/", htm="GET", ath=ath)
        self.assertEqual(self.client.get(BASE + "status/", **headers).status_code, 200)

    def introspection_service(self, **extra):
        service = ServiceAccount(name="Synthetic inspector", client_id="synthetic-inspector",
                                 scopes=["sso.device.introspect"], audiences=["arna-sso-devices"], **extra)
        service.set_client_secret("synthetic-only")
        service.save()
        response = self.client.post("/api/auth/service-token/", {"client_id": service.client_id,
                                    "client_secret": "synthetic-only", "audience": "arna-sso-devices"}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + response.data["access"])
        return service

    def test_backend_introspection_validates_service_and_active_assignment(self):
        pair = self.pair()
        service = self.introspection_service(organization_id=self.org.pk, tenant_id=self.tenant)
        payload = {"access_token": pair["access_token"], "audience": "photobooth-api"}
        self.assertTrue(self.client.post(BASE + "introspect/", payload, format="json").data["active"])
        DeviceRegistration.objects.filter(pk=pair["device_id"]).update(is_active=False)
        self.assertEqual(self.client.post(BASE + "introspect/", payload, format="json").data, {"active": False})
        service.is_active = False
        service.save()
        self.assertEqual(self.client.post(BASE + "introspect/", payload, format="json").status_code, 401)

    def test_tenant_scoped_service_cannot_inspect_other_tenant(self):
        pair = self.pair()
        self.introspection_service(organization_id=self.org_b.pk, tenant_id=self.tenant_b)
        response = self.client.post(BASE + "introspect/", {"access_token": pair["access_token"], "audience": "photobooth-api"}, format="json")
        self.assertEqual(response.data, {"active": False})

    def test_human_or_device_token_cannot_call_backend_introspection(self):
        pair = self.pair()
        self.client.force_authenticate(user=None)
        payload = {"access_token": pair["access_token"], "audience": "photobooth-api"}
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + pair["access_token"])
        self.assertEqual(self.client.post(BASE + "introspect/", payload, format="json").status_code, 401)

    def test_introspection_service_cannot_have_additional_privileges(self):
        service = ServiceAccount(name="Mixed", client_id="mixed", scopes=["sso.device.introspect", "other.scope"], audiences=["arna-sso-devices"])
        service.set_client_secret("synthetic-only")
        service.save()
        self.assertEqual(self.client.post("/api/auth/service-token/", {"client_id": service.client_id,
                          "client_secret": "synthetic-only", "audience": "arna-sso-devices"}, format="json").status_code, 400)

    def test_migration_revokes_unverified_pairings_without_changing_humans(self):
        pair = self.pair()
        pending = self.authorize().data
        module = importlib.import_module("authentication.migrations.0015_device_pairing_security")
        module.invalidate_unverified_pairings(apps, Mock(connection=connection))
        self.assertFalse(DeviceRegistration.objects.get(pk=pair["device_id"]).is_active)
        self.assertIsNotNone(DeviceRefreshCredential.objects.get().revoked_at)
        self.assertEqual(self.token(pending).data["error"], "access_denied")
        self.assertTrue(User.objects.get(pk=self.owner.pk).is_active)
        self.assertEqual(self.refresh(pair).status_code, 400)

    def test_permission_revoked_during_tenant_lookup_cannot_approve(self):
        grant = self.authorize().data
        def change_owner(*args, **kwargs):
            Organization.objects.filter(pk=self.org.pk).update(owner=self.other)
            return self.tenant_response(*args, **kwargs)
        self.lookup.side_effect = change_owner
        self.assertEqual(self.decision(grant).status_code, 403)
        self.assertFalse(DeviceRegistration.objects.exists())

    def test_openapi_includes_versioned_device_contract(self):
        response = self.client.get("/swagger/", HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200)
        schema = response.data
        self.assertTrue(any(path.endswith("/v1/devices/review/") for path in schema["paths"]))
        self.assertIn("DeviceInventoryResponse", schema["definitions"])
        self.assertIn("DeviceError", schema["definitions"])


class DeviceConcurrencyTests(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.owner = User.objects.create_user(email="concurrent-device@example.test", password=None, is_active=True)
        self.org = Organization.objects.create(name="Concurrent Device", owner=self.owner, package_type="Basic")
        self.tenant = str(uuid.uuid4())
        OrganizationMember.objects.create(user=self.owner, organization=self.org, active_tenant_id=self.tenant)
        self.verifier = patch("authentication.device_context.verify_tenant", return_value=None).start()
        self.addCleanup(patch.stopall)
        self.client = APIClient()
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(BASE + "authorize/", {"client_id": "concurrent-device", "device_name": "Race kiosk",
            "organization_id": str(self.org.pk), "tenant_id": self.tenant, "audience": "photobooth-api",
            "scopes": ["photobooth.session"]}, format="json")
        self.assertEqual(response.status_code, 201)
        self.grant = response.data

    def race(self, path, payload):
        barrier = Barrier(2)
        owner_id = self.owner.pk
        def worker():
            close_old_connections()
            try:
                client = APIClient()
                client.force_authenticate(user=User.objects.get(pk=owner_id))
                barrier.wait(timeout=10)
                response = client.post(BASE + path, payload, format="json")
                return response.status_code, response.data
            finally:
                connections.close_all()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            return [future.result(timeout=20) for future in futures]

    def approve(self):
        payload = {"user_code": self.grant["user_code"], "organization_id": str(self.org.pk), "action": "approve"}
        self.assertEqual(self.client.post(BASE + "verification/", payload, format="json").status_code, 200)

    def test_parallel_approvals_make_one_decision(self):
        results = self.race("verification/", {"user_code": self.grant["user_code"], "organization_id": str(self.org.pk), "action": "approve"})
        self.assertEqual(sorted(code for code, _ in results), [200, 400])
        self.assertEqual(DeviceRegistration.objects.count(), 1)
        self.assertEqual(DeviceRegistration.objects.get().credential_version, 1)

    def test_parallel_token_exchange_consumes_grant_once(self):
        self.approve()
        results = self.race("token/", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": self.grant["device_code"]})
        self.assertEqual(sorted(code for code, _ in results), [200, 400])
        self.assertEqual(DeviceRefreshCredential.objects.count(), 1)

    def test_parallel_refresh_rotates_once(self):
        self.approve()
        pair = self.client.post(BASE + "token/", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": self.grant["device_code"]}, format="json").data
        results = self.race("refresh/", {"refresh_token": pair["refresh_token"]})
        self.assertEqual(sorted(code for code, _ in results), [200, 400])
        self.assertEqual(DeviceRefreshCredential.objects.filter(used_at__isnull=True, revoked_at__isnull=True).count(), 1)
