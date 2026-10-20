from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase
from rest_framework.test import APIClient

from authentication.models import User
from organization.models import Organization, OrganizationMember
from iam.models import Permission
from iam.serializers import PermissionSerializer


class PermissionDuplicateTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='permission-owner@example.test', is_active=True)
        self.org = Organization.objects.create(owner=self.owner, name='Permission fixture', package_type='test')
        self.membership = OrganizationMember.objects.create(user=self.owner, organization=self.org)
        self.client = APIClient()
        self.client.force_authenticate(self.owner)
        self.url = '/api/iam/permissions/'

    def test_seeded_photobooth_permission_returns_clear_400(self):
        response = self.client.post(self.url, {'name':'commerce.orders.read'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('already exists', str(response.data['name']))
        self.assertEqual(Permission.objects.filter(organization=self.org, name='commerce.orders.read').count(), 1)

    def test_new_permission_is_created_under_active_org(self):
        response = self.client.post(self.url, {'name':'photobooth.sessions.execute'})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(str(response.data['organization']), str(self.org.pk))

    def test_same_name_in_another_org_does_not_block_create(self):
        other = Organization.objects.create(owner=self.owner, name='Another org', package_type='test')
        Permission.objects.create(organization=other, name='photobooth.sessions.execute')
        response = self.client.post(self.url, {'name':'photobooth.sessions.execute','organization':str(other.pk)})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(str(response.data['organization']), str(self.org.pk))

    def test_duplicate_rename_does_not_partially_update_description(self):
        permission = Permission.objects.create(organization=self.org, name='photobooth.other', description='original')
        response = self.client.patch(self.url+str(permission.pk)+'/', {'name':'commerce.orders.read','description':'changed'})
        self.assertEqual(response.status_code, 400)
        permission.refresh_from_db()
        self.assertEqual(permission.name, 'photobooth.other')
        self.assertEqual(permission.description, 'original')

    def test_description_only_edit_and_unchanged_name_remain_valid(self):
        permission = Permission.objects.get(organization=self.org, name='commerce.orders.read')
        response = self.client.patch(self.url+str(permission.pk)+'/', {'name':permission.name,'description':'updated'})
        self.assertEqual(response.status_code, 200)

    def test_missing_context_does_not_create_a_global_permission(self):
        self.membership.is_session_active = False
        self.membership.save()
        response = self.client.post(self.url, {'name':'photobooth.no.context'})
        self.assertIn(response.status_code, (400,403))
        self.assertFalse(Permission.objects.filter(name='photobooth.no.context').exists())


class ConcurrentPermissionTests(TransactionTestCase):
    def test_two_owner_requests_for_same_name_create_one_permission(self):
        if connection.vendor != 'postgresql':
            self.skipTest('Requires PostgreSQL concurrency and real unique constraint')
        owner = User.objects.create_user(email='permission-race@example.test', is_active=True)
        org = Organization.objects.create(owner=owner, name='Race fixture', package_type='test')
        OrganizationMember.objects.create(user=owner, organization=org)
        barrier = Barrier(2, timeout=15)
        original = PermissionSerializer.validate_name

        def validate(serializer, value):
            result = original(serializer, value)
            barrier.wait()
            return result

        def create(_):
            close_old_connections()
            try:
                client = APIClient()
                client.force_authenticate(owner)
                return client.post('/api/iam/permissions/', {'name':'photobooth.racing'}).status_code
            finally:
                close_old_connections()

        with patch.object(PermissionSerializer, 'validate_name', validate):
            with ThreadPoolExecutor(max_workers=2) as pool:
                statuses = list(pool.map(create, range(2)))
        self.assertCountEqual(statuses, [201,400])
        self.assertEqual(Permission.objects.filter(organization=org,name='photobooth.racing').count(), 1)
