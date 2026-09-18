import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0010_serviceaccount_audiences"),
        ("organization", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="DeviceRegistration",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("client_id", models.CharField(max_length=120, unique=True)),
                ("display_name", models.CharField(max_length=120)),
                ("tenant_id", models.UUIDField()),
                ("audience", models.CharField(max_length=120)),
                ("scopes", models.JSONField(blank=True, default=list)),
                ("public_key_thumbprint", models.CharField(blank=True, max_length=128)),
                ("is_active", models.BooleanField(default=True)),
                ("approved_at", models.DateTimeField(blank=True, null=True)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("approved_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="authentication.user")),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="organization.organization")),
            ],
        ),
        migrations.CreateModel(
            name="DeviceAuthorizationGrant",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("device_code_hash", models.CharField(max_length=64, unique=True)),
                ("user_code_hash", models.CharField(max_length=64, unique=True)),
                ("client_id", models.CharField(db_index=True, max_length=120)),
                ("device_name", models.CharField(max_length=120)),
                ("tenant_id", models.UUIDField()),
                ("audience", models.CharField(max_length=120)),
                ("scopes", models.JSONField(blank=True, default=list)),
                ("public_key_thumbprint", models.CharField(blank=True, max_length=128)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("interval_seconds", models.PositiveIntegerField(default=5)),
                ("last_polled_at", models.DateTimeField(blank=True, null=True)),
                ("approved_at", models.DateTimeField(blank=True, null=True)),
                ("denied_at", models.DateTimeField(blank=True, null=True)),
                ("consumed_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("approved_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="authentication.user")),
                ("approved_registration", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="authentication.deviceregistration")),
            ],
        ),
        migrations.CreateModel(
            name="DeviceRefreshCredential",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("registration", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="refresh_credentials", to="authentication.deviceregistration")),
            ],
        ),
        migrations.AddIndex(
            model_name="deviceregistration",
            index=models.Index(fields=["organization", "tenant_id", "is_active"], name="authentication_organiz_6bb37f_idx"),
        ),
    ]
