from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from authentication.models import ServiceAccount
from iam.models import Permission, ProductManagedRole, ProductProvisioning, ProductProvisioningEvent, Role
from organization.models import Organization, OrganizationMember


class ProductCatalogProvisioningTests(APITestCase):
    def setUp(self):
        owner = get_user_model().objects.create_user(email="catalog-owner@example.test", password="password")
        self.organization = Organization.objects.create(
            name="Catalog Tenant", owner=owner, package_type="Enterprise"
        )
        OrganizationMember.objects.create(
            user=owner, organization=self.organization, is_session_active=True
        )
        self.service = ServiceAccount(
            name="ArnaOS Provisioner",
            client_id="arnaos-provisioner-test",
            organization_id=self.organization.id,
            scopes=["iam.catalog.provision:arnaos"],
            audiences=["sso-iam"],
        )
        self.service.set_client_secret("test-secret")
        self.service.save()
        self.url = "/api/iam/product-catalogs/arnaos/provision/"

    def token(self, audience="sso-iam"):
        response = self.client.post("/api/auth/service-token/", {
            "client_id": self.service.client_id,
            "client_secret": "test-secret",
            "audience": audience,
        })
        self.assertEqual(response.status_code, 200)
        return response.data["access"]

    def catalog(self, version=1):
        return {
            "catalog_version": version,
            "permissions": [
                {"name": "arnaos.work.view", "description": "View work."},
                {"name": "world.workspace.enter", "description": "Enter workspace."},
            ],
            "roles": [{
                "key": "employee",
                "name": "ArnaOS Employee",
                "description": "Baseline employee access.",
                "permissions": ["arnaos.work.view", "world.workspace.enter"],
            }],
        }

    def provision(self, payload=None, token=None):
        return self.client.post(
            self.url,
            payload or self.catalog(),
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token or self.token()}",
        )

    def test_provisions_an_organization_catalog_atomically_and_idempotently(self):
        first = self.provision()
        second = self.provision()

        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.data["created"])
        self.assertEqual(first.data["result"]["permissions_created"], 2)
        self.assertEqual(first.data["result"]["roles_created"], 1)
        self.assertEqual(second.status_code, 200)
        self.assertFalse(second.data["created"])
        self.assertEqual(second.data["result"]["permissions_created"], 0)
        self.assertEqual(second.data["result"]["roles_created"], 0)
        self.assertEqual(Permission.objects.filter(organization=self.organization).count(), 2)
        role = Role.objects.get(organization=self.organization, name="ArnaOS Employee")
        self.assertEqual(set(role.permissions.values_list("name", flat=True)), {
            "arnaos.work.view", "world.workspace.enter"
        })
        self.assertEqual(ProductProvisioning.objects.get().catalog_version, 1)
        self.assertEqual(ProductProvisioningEvent.objects.count(), 2)

    def test_upgrade_is_additive_and_preserves_tenant_customization(self):
        self.provision()
        managed = ProductManagedRole.objects.select_related("role").get(managed_key="employee")
        managed.role.name = "Our Employees"
        managed.role.save(update_fields=["name"])
        extra = Permission.objects.create(
            organization=self.organization, name="arnaos.tenant.extra", description="Tenant extra."
        )
        managed.role.permissions.add(extra)
        upgraded = self.catalog(version=2)
        upgraded["permissions"].append({"name": "arnaos.agent.use", "description": "Use agents."})
        upgraded["roles"][0]["permissions"].append("arnaos.agent.use")

        response = self.provision(upgraded)

        self.assertEqual(response.status_code, 200)
        managed.refresh_from_db()
        self.assertEqual(managed.role.name, "Our Employees")
        self.assertEqual(managed.catalog_version, 2)
        self.assertEqual(
            set(managed.role.permissions.values_list("name", flat=True)),
            {"arnaos.work.view", "world.workspace.enter", "arnaos.agent.use", "arnaos.tenant.extra"},
        )

    def test_rejects_scope_audience_namespace_binding_and_downgrade_violations(self):
        forbidden_audience = self.client.post("/api/auth/service-token/", {
            "client_id": self.service.client_id,
            "client_secret": "test-secret",
            "audience": "storage",
        })
        self.assertEqual(forbidden_audience.status_code, 403)

        self.service.scopes = []
        self.service.save(update_fields=["scopes"])
        missing_scope = self.provision(token=self.token())
        self.assertEqual(missing_scope.status_code, 403)
        self.service.scopes = ["iam.catalog.provision:arnaos"]
        self.service.save(update_fields=["scopes"])

        invalid = self.catalog()
        invalid["permissions"][0]["name"] = "finance.admin"
        self.assertEqual(self.provision(invalid).status_code, 400)

        self.service.organization_id = None
        self.service.save(update_fields=["organization_id"])
        self.assertEqual(self.provision(token=self.token()).status_code, 403)
        self.service.organization_id = self.organization.id
        self.service.save(update_fields=["organization_id"])

        self.assertEqual(self.provision(self.catalog(version=2)).status_code, 200)
        self.assertEqual(self.provision(self.catalog(version=1)).status_code, 409)

    def test_rejects_invalid_manifests_and_unmanaged_role_name_collisions(self):
        malformed = self.provision(token="not-a-jwt")
        self.assertEqual(malformed.status_code, 401)

        duplicate = self.catalog()
        duplicate["permissions"].append(dict(duplicate["permissions"][0]))
        self.assertEqual(self.provision(duplicate).status_code, 400)

        unknown = self.catalog()
        unknown["roles"][0]["permissions"].append("arnaos.missing")
        self.assertEqual(self.provision(unknown).status_code, 400)

        Role.objects.create(organization=self.organization, name="ArnaOS Employee")
        collision = self.provision()
        self.assertEqual(collision.status_code, 400)
        self.assertFalse(ProductProvisioning.objects.exists())
