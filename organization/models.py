import uuid
from django.db import models
from authentication.models import User  # Assuming User model is in the authentication app

class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)  # The user who owns the organization
    package_type = models.CharField(max_length=50)  # e.g., 'Basic', 'Advanced'
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
