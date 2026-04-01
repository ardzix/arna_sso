from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from organization.models import Organization, OrganizationMember
from iam.models import Role, Permission, UserRole

User = get_user_model()

class IAMMultiTenancyTests(APITestCase):
    def setUp(self):
        # 1. Setup Users
        self.owner_a = User.objects.create_user(email='owner@a.com', password='password')
        self.owner_b = User.objects.create_user(email='owner@b.com', password='password')
        self.staff_a = User.objects.create_user(email='staff@a.com', password='password')
        self.stranger = User.objects.create_user(email='stranger@x.com', password='password')

        # 2. Setup Organizations
        self.org_a = Organization.objects.create(name='Company A', owner=self.owner_a, package_type='Basic')
        self.org_b = Organization.objects.create(name='Company B', owner=self.owner_b, package_type='Basic')

        # 3. Setup Memberships
        OrganizationMember.objects.create(user=self.staff_a, organization=self.org_a)
        # Owner A is implicitly owner, but for IAM logic ensuring they are member is safer if logic relies on members
        OrganizationMember.objects.create(user=self.owner_a, organization=self.org_a)
        OrganizationMember.objects.create(user=self.owner_b, organization=self.org_b)

        # 4. Setup Permissions
        self.perm = Permission.objects.create(name='test.perm', description='Test')

        # 5. Setup Roles
        self.role_global = Role.objects.create(name='Global Role') # org=None
        self.role_a = Role.objects.create(name='Role A', organization=self.org_a)
        self.role_b = Role.objects.create(name='Role B', organization=self.org_b)

    def test_role_isolation(self):
        """Owner A should see Role A & Global, but NOT Role B"""
        self.client.force_authenticate(user=self.owner_a)
        response = self.client.get('/api/iam/roles/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role_ids = [r['id'] for r in response.data]
        
        self.assertIn(str(self.role_a.id), role_ids, "Owner A should see Role A")
        self.assertIn(str(self.role_global.id), role_ids, "Owner A should see Global Role")
        self.assertNotIn(str(self.role_b.id), role_ids, "Owner A should NOT see Role B")

    def test_assign_role_success_own_member(self):
        """Owner A assigns Role A to Staff A (Member) -> Success"""
        self.client.force_authenticate(user=self.owner_a)
        data = {
            'user': str(self.staff_a.id),
            'role': str(self.role_a.id)
        }
        response = self.client.post('/api/iam/user-roles/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserRole.objects.count(), 1)

    def test_assign_role_fail_non_member(self):
        """Owner A assigns Role A to Stranger (Not Member) -> Fail"""
        self.client.force_authenticate(user=self.owner_a)
        data = {
            'user': str(self.stranger.id),
            'role': str(self.role_a.id)
        }
        response = self.client.post('/api/iam/user-roles/', data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("not a member", str(response.data))

    def test_assign_global_role_success(self):
        """Owner A assigns Global Role to Staff A -> Success"""
        self.client.force_authenticate(user=self.owner_a)
        # Note: Logic for Global Role assignment validation might need review.
        # Current logic: if role.organization exists, check member. 
        # If role.organization is Null (Global), the check is skipped, so ANYONE can be assigned?
        # Let's verify expectation. Ideally Owner A can assign Global Role to HIS members.
        # But if Global Role has NO org, the serializer check `if role.organization:` is skipped.
        # Use case: Assign 'Reader' to Staff A.
        data = {
            'user': str(self.staff_a.id),
            'role': str(self.role_global.id)
        }
        response = self.client.post('/api/iam/user-roles/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_direct_permission_via_member_update(self):
        """Owner A grants direct permission to Staff A via OrganizationMember"""
        self.client.force_authenticate(user=self.owner_a)
        
        # Get Member ID
        member = OrganizationMember.objects.get(user=self.staff_a, organization=self.org_a)
        
        # Update Member permissions
        data = {
            'permissions': [self.perm.id]
        }
        # Update member via nested endpoint
        response = self.client.patch(f'/api/organizations/{self.org_a.id}/members/{member.id}/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        member.refresh_from_db()
        self.assertIn(self.perm, member.permissions.all())
