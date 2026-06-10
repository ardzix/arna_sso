import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("authentication", "0006_corsallowedorigin")]

    operations = [
        migrations.CreateModel(
            name="ServiceAccount",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=120)),
                ("client_id", models.CharField(max_length=120, unique=True)),
                ("client_secret_hash", models.CharField(max_length=255)),
                ("organization_id", models.UUIDField(blank=True, null=True)),
                ("scopes", models.JSONField(blank=True, default=list)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
