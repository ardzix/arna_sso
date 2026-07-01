import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0007_serviceaccount"),
    ]

    operations = [
        migrations.CreateModel(
            name="SSOAuthorizationCode",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("code_hash", models.CharField(max_length=64, unique=True)),
                ("client_id", models.CharField(max_length=120)),
                ("redirect_uri", models.URLField(max_length=500)),
                ("code_challenge", models.CharField(max_length=128)),
                (
                    "code_challenge_method",
                    models.CharField(
                        choices=[("S256", "S256"), ("plain", "plain")],
                        default="S256",
                        max_length=10,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField()),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sso_auth_codes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at",),
            },
        ),
        migrations.AddIndex(
            model_name="ssoauthorizationcode",
            index=models.Index(fields=["client_id", "redirect_uri"], name="authenticat_client__b56e5d_idx"),
        ),
        migrations.AddIndex(
            model_name="ssoauthorizationcode",
            index=models.Index(fields=["expires_at"], name="authenticat_expires_448dcf_idx"),
        ),
    ]
