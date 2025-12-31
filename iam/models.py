from django.db import models
import uuid
from authentication.models import User


class Permission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    # Multi-Tenancy Key:
    # - If NULL: This is a GLOBAL Role (visible to all organizations).
    # - If SET: This is an ORGANIZATION Role (private to that specific organization).
    # Uses Lazy Reference ('app.Model') to avoid Circular Import errors.
    # ForeignKey = Many-to-One Relationship (One Org has many Roles).
    organization = models.ForeignKey('organization.Organization', on_delete=models.CASCADE, null=True, blank=True, related_name='roles')
    # Many-to-Many Relationship:
    # One Role has many Permissions. One Permission can belong to many Roles.
    # Django automatically creates a hidden intermediate table (iam_role_permissions).
    permissions = models.ManyToManyField(Permission, related_name='roles')
    description = models.TextField(blank=True)

    class Meta:
        unique_together = ('organization', 'name')

    def __str__(self):
        return self.name


class UserRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization_member = models.ForeignKey('organization.OrganizationMember', on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.organization_member.user.email} - {self.role.name}"

class UserPermission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    permissions = models.ManyToManyField('iam.Permission', blank=True, related_name='direct_members')
    organization_member = models.ForeignKey('organization.OrganizationMember', on_delete=models.CASCADE)
    assigned_at = models.DateTimeField(auto_now_add=True)

    