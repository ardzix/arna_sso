import uuid
from django.db import models
from authentication.models import User

class UserProfile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    full_name = models.CharField(max_length=100, blank=True, null=True)
    bio = models.TextField(blank=True)
    profile_picture = models.URLField(blank=True, null=True)  # URLField instead of ImageField
    phone_number = models.CharField(max_length=15, blank=True)
    preferences = models.JSONField(blank=True, null=True)  # Store user-specific preferences in JSON

    def __str__(self):
        return self.user.email
