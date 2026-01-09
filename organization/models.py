import uuid
from django.db import models
from authentication.models import User  # Assuming User model is in the authentication app

class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    # The "Super User" of this tenant. Has absolute power over this organization.
    owner = models.ForeignKey(User, on_delete=models.CASCADE) 
    package_type = models.CharField(max_length=50)  # e.g., 'Basic', 'Enterprise'
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class OrganizationMember(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='organization_memberships')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='members')
    # DIRECT PERMISSIONS:
    # Special permissions given to this specific user ONLY in this specific organization.
    # These are separate from Roles. Useful for "exceptions" (e.g., a guest who needs just 1 extra access).
    joined_at = models.DateTimeField(auto_now_add=True)
    is_session_active = models.BooleanField(default=True) 

    class Meta:
        unique_together = ('user', 'organization')

    def __str__(self):
        return f"{self.user.email} in {self.organization.name}"
