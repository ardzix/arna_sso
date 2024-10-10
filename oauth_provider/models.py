import uuid
from django.db import models
from authentication.models import User


class OAuthProvider(models.Model):
    PROVIDER_CHOICES = (
        ('google', 'Google'),
        ('facebook', 'Facebook'),
        # Add more providers as needed
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, choices=PROVIDER_CHOICES)
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    authorization_url = models.URLField()
    token_url = models.URLField()
    scope = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.name


class OAuthToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    provider = models.ForeignKey(OAuthProvider, on_delete=models.CASCADE)
    access_token = models.CharField(max_length=255)
    refresh_token = models.CharField(max_length=255, blank=True, null=True)
    expires_in = models.IntegerField()
    token_type = models.CharField(max_length=50, default='Bearer')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.provider.name}"
