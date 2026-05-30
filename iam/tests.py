"""Integration tests for IAM multi-tenant access behavior."""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from iam.models import Permission, Role, UserPermission, UserRole
from organization.models import Organization, OrganizationMember

User = get_user_model()


class IAMMultiTenancyTests(APITestCase):
    """Validate organization-scoped visibility and role assignment rules."""

    def setUp(self):
        """Create users, organizations, memberships, and org-scoped IAM fixtures."""
        self.owner_a = User.objects.create_user(email="owner@a.com", password="password")
        self.owner_b = User.objects.create_user(email="owner@b.com", password="password")
        self.staff_a = User.objects.create_user(email="staff@a.com", password="password")
        self.stranger = User.objects.create_user(email="stranger@x.com", password="password")

        self.org_a = Organization.objects.create(name="Company A", owner=self.owner_a, package_type="Basic")
        self.org_b = Organization.objects.create(name="Company B", owner=self.owner_b, package_type="Basic")

        self.member_owner_a = OrganizationMember.objects.create(
            user=self.owner_a,
            organization=self.org_a,
            is_session_active=True,
        )
        self.member_owner_b = OrganizationMember.objects.create(
            user=self.owner_b,
            organization=self.org_b,
            is_session_active=True,
        )
        self.member_staff_a = OrganizationMember.objects.create(
            user=self.staff_a,
            organization=self.org_a,
            is_session_active=False,
        )

        self.perm_a = Permission.objects.create(
            name="organization.manage_roles",
            description="Can manage roles in org A.",
            organization=self.org_a,
        )
        self.perm_b = Permission.objects.create(
            name="organization.manage_roles",
            description="Can manage roles in org B.",
            organization=self.org_b,
        )

        self.role_a = Role.objects.create(name="Role A", organization=self.org_a)
        self.role_a.permissions.add(self.perm_a)
        self.role_b = Role.objects.create(name="Role B", organization=self.org_b)
        self.role_b.permissions.add(self.perm_b)

    def test_role_isolation(self):
        """Owner A should only see roles from active organization A."""
        self.client.force_authenticate(user=self.owner_a)
        response = self.client.get("/api/iam/roles/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role_ids = [r["id"] for r in response.data]
        self.assertIn(str(self.role_a.id), role_ids)
        self.assertNotIn(str(self.role_b.id), role_ids)

    def test_assign_role_success_own_member(self):
        """Owner A can assign org A role to org A member."""
        self.client.force_authenticate(user=self.owner_a)
        payload = {"organization_member": str(self.member_staff_a.id), "role": str(self.role_a.id)}
        response = self.client.post("/api/iam/user-roles/", payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            UserRole.objects.filter(organization_member=self.member_staff_a, role=self.role_a).exists()
        )

    def test_assign_role_fail_non_member(self):
        """Owner A cannot assign role to a user outside organization A."""
        self.client.force_authenticate(user=self.owner_a)
        foreign_member = OrganizationMember.objects.create(user=self.stranger, organization=self.org_b)
        payload = {"organization_member": str(foreign_member.id), "role": str(self.role_a.id)}
        response = self.client.post("/api/iam/user-roles/", payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_direct_permission_assignment(self):
        """Owner A can assign direct permission through IAM user-permissions API."""
        self.client.force_authenticate(user=self.owner_a)
        payload = {
            "organization_member": str(self.member_staff_a.id),
            "permission_ids": [str(self.perm_a.id)],
        }
        response = self.client.post("/api/iam/user-permissions/", payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        direct_grant = UserPermission.objects.filter(
            organization_member=self.member_staff_a,
            permissions=self.perm_a,
        )
        self.assertTrue(direct_grant.exists())
