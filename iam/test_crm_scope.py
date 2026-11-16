import unittest
from iam.crm_scope import resolve_crm_grant

A = "10996862-26be-4c7a-8a05-acb814f77975"
B = "00000000-0000-4000-8000-000000000002"


class CRMScopePolicyTests(unittest.TestCase):
    def grant(self, tenant=A, permissions=None):
        return {"tenant_id": tenant, "permissions": permissions or ["crm.manage"]}

    def test_one_grant_never_inherits_other_org_tenants(self):
        self.assertEqual(resolve_crm_grant([A, B], [self.grant()]), (A, ["crm.manage"]))

    def test_no_grant_is_denied(self):
        with self.assertRaises(ValueError):
            resolve_crm_grant([A], [])

    def test_unverified_tenant_is_denied(self):
        with self.assertRaises(ValueError):
            resolve_crm_grant([B], [self.grant()])

    def test_selector_is_not_authorization(self):
        with self.assertRaises(ValueError):
            resolve_crm_grant([A, B], [self.grant()], B)

    def test_multiple_grants_require_selection(self):
        with self.assertRaises(ValueError):
            resolve_crm_grant([A, B], [self.grant(), self.grant(B)])

    def test_permissions_do_not_leak_between_tenants(self):
        self.assertEqual(resolve_crm_grant([A, B], [self.grant(), self.grant(B, ["crm.read"])], B), (B, ["crm.read"]))

    def test_admin_permissions_are_rejected(self):
        with self.assertRaises(ValueError):
            resolve_crm_grant([A], [self.grant(permissions=["organization.admin"])])

    def test_malformed_uuid_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_crm_grant(["not-a-uuid"], [self.grant()])

    def test_malformed_permissions_are_rejected(self):
        for permissions in (None, "crm.manage", [True], [], ["crm.manage", {}]):
            with self.subTest(permissions=permissions), self.assertRaises(ValueError):
                resolve_crm_grant([A], [{"tenant_id": A, "permissions": permissions}])

if __name__ == "__main__":
    unittest.main()
