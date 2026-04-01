from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from authentication.models import User
from .models import Organization, OrganizationMember
from iam.models import Role, UserRole, Permission

class OrganizationMemberViewSetTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        
        # Create Users
        self.owner = User.objects.create_user(email='owner@example.com', password='password123')
        self.admin_user = User.objects.create_user(email='admin@example.com', password='password123')
        self.regular_user = User.objects.create_user(email='user@example.com', password='password123')
        self.new_user_to_add = User.objects.create_user(email='newbie@example.com', password='password123')
        
        # Create Organization
        self.org = Organization.objects.create(name="Test Org", owner=self.owner)
        
        # Owner Membership (implicitly created usually, but ensuring it here for test setup if logic requires)
        self.owner_member = OrganizationMember.objects.create(user=self.owner, organization=self.org)

        # Admin User Membership
        self.admin_member = OrganizationMember.objects.create(user=self.admin_user, organization=self.org)
        
        # URLs
        self.list_url = reverse('organizationmember-list')
        
    def test_owner_can_add_member(self):
        self.client.force_authenticate(user=self.owner)
        data = {
            "organization": self.org.id,
            "user": self.new_user_to_add.id
        }
        response = self.client.post(self.list_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
    def test_regular_user_cannot_add_member(self):
        # Regular user matches "admin_user" but WITHOUT permissions/roles yet
        self.client.force_authenticate(user=self.admin_user)
        data = {
            "organization": self.org.id,
            "user": self.new_user_to_add.id
        }
        response = self.client.post(self.list_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("You do not have permission", str(response.data))

    def test_admin_user_with_role_can_add_member(self):
        # 1. Create Permission
        perm = Permission.objects.create(name='organization.manage_members')
        
        # 2. Create Role with Permission
        role = Role.objects.create(name='Org Admin', organization=self.org)
        role.permissions.add(perm)
        
        # 3. Assign Role to Admin User
        UserRole.objects.create(organization_member=self.admin_member, role=role)
        
        # 4. Test
        self.client.force_authenticate(user=self.admin_user)
        data = {
            "organization": self.org.id,
            "user": self.new_user_to_add.id
        }
        response = self.client.post(self.list_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
