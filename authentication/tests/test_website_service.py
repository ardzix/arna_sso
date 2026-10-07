import uuid

from django.db import IntegrityError, transaction
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import UntypedToken

from authentication.models import ServiceAccount


class WebsiteServiceTokenTests(APITestCase):
    def setUp(self):
        self.service = ServiceAccount(
            name="Tenant website test", client_id="test-tenant-website",
            organization_id=uuid.uuid4(), tenant_id=uuid.uuid4(),
            scopes=["crm.website_chat"], audiences=["arna-crm"],
        )
        self.service.set_client_secret("isolated-test-secret")
        self.service.save()
        self.payload = {"client_id": self.service.client_id, "client_secret": "isolated-test-secret", "audience": "arna-crm"}

    def test_registered_ownership_is_signed_and_request_cannot_override_it(self):
        response = self.client.post(reverse("service_token"), {
            **self.payload, "org_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
            "scope": "crm.manage", "tenant_ids": [str(uuid.uuid4())],
        }, format="json")
        self.assertEqual(response.status_code, 200)
        token = UntypedToken(response.data["access"])
        self.assertEqual(token["token_type"], "service")
        self.assertEqual(token["principal_type"], "service")
        self.assertEqual(token["org_id"], str(self.service.organization_id))
        self.assertEqual(token["tenant_id"], str(self.service.tenant_id))
        self.assertEqual(token["scope"], "crm.website_chat")
        self.assertEqual(token["scopes"], ["crm.website_chat"])
        self.assertEqual(token["aud"], "arna-crm")
        self.assertNotIn("tenant_ids", token)
        self.assertNotIn("permissions", token)
        self.assertLessEqual(token["exp"] - token["iat"], 300)

    def test_missing_binding_or_extra_scope_does_not_issue_a_token(self):
        for changes in (
            {"tenant_id": None},
            {"tenant_id": None, "organization_id": None},
            {"scopes": ["crm.website_chat", "crm.manage"]},
            {"audiences": ["arna-crm", "storage"]},
        ):
            for name, value in changes.items(): setattr(self.service, name, value)
            self.service.save()
            response = self.client.post(reverse("service_token"), self.payload, format="json")
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("access", response.data)
            self.service.tenant_id, self.service.organization_id = uuid.uuid4(), uuid.uuid4()
            self.service.scopes, self.service.audiences = ["crm.website_chat"], ["arna-crm"]

    def test_disabled_account_or_wrong_secret_cannot_renew(self):
        response = self.client.post(reverse("service_token"), {**self.payload, "client_secret": "wrong"}, format="json")
        self.assertEqual(response.status_code, 401)
        self.service.is_active = False
        self.service.save(update_fields=["is_active"])
        self.assertEqual(self.client.post(reverse("service_token"), self.payload, format="json").status_code, 401)

    def test_tenant_binding_requires_an_organization_at_database_level(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            ServiceAccount.objects.create(name="Invalid", client_id="invalid-org", tenant_id=uuid.uuid4())
