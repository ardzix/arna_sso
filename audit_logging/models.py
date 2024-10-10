import uuid
from django.db import models
from authentication.models import User  # Assuming User model is in the authentication app

class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # The user performing the action
    action = models.CharField(max_length=255)  # e.g., 'login', 'role_change', 'permission_update'
    metadata = models.JSONField()  # Any additional data (e.g., IP address)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.action}"
