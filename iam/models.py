from django.db import models
import uuid
from authentication.models import User


class Permission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    # Multi-Tenancy Key:
    # All permissions are ORGANIZATION-SPECIFIC (private to that specific organization).
    # No global permissions allowed - this is a multi-tenant IAM service.
    organization = models.ForeignKey('organization.Organization', on_delete=models.CASCADE, related_name='permissions')
    description = models.TextField(blank=True)

    class Meta:
        unique_together = ('organization', 'name')

    def __str__(self):
        return self.name


class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    # Multi-Tenancy Key:
    # All roles are ORGANIZATION-SPECIFIC (private to that specific organization).
    # No global roles allowed - this is a multi-tenant IAM service.
    # Note: Field is nullable in DB for backward compatibility, but views/serializers enforce organization requirement.
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


class ProductProvisioning(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organization.Organization', on_delete=models.CASCADE, related_name='product_provisionings'
    )
    product_key = models.SlugField(max_length=80)
    catalog_version = models.PositiveIntegerField(default=1)
    manifest_hash = models.CharField(max_length=64)
    service_client_id = models.CharField(max_length=120)
    provisioned_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('organization', 'product_key')


class ProductManagedRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organization.Organization', on_delete=models.CASCADE, related_name='product_managed_roles'
    )
    product_key = models.SlugField(max_length=80)
    managed_key = models.SlugField(max_length=80)
    role = models.OneToOneField(Role, on_delete=models.CASCADE, related_name='product_management')
    catalog_version = models.PositiveIntegerField(default=1)

    class Meta:
        unique_together = ('organization', 'product_key', 'managed_key')


class ProductProvisioningEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organization.Organization', on_delete=models.CASCADE, related_name='product_provisioning_events'
    )
    product_key = models.SlugField(max_length=80)
    catalog_version = models.PositiveIntegerField()
    service_client_id = models.CharField(max_length=120)
    result = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

