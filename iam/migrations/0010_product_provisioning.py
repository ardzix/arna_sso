import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("iam", "0009_drop_legacy_global_name_indexes"),
        ("organization", "0004_organizationmember_unique_active_session_per_user"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProductProvisioning",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("product_key", models.SlugField(max_length=80)),
                ("catalog_version", models.PositiveIntegerField(default=1)),
                ("manifest_hash", models.CharField(max_length=64)),
                ("service_client_id", models.CharField(max_length=120)),
                ("provisioned_at", models.DateTimeField(auto_now=True)),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="product_provisionings", to="organization.organization")),
            ],
            options={"unique_together": {("organization", "product_key")}},
        ),
        migrations.CreateModel(
            name="ProductManagedRole",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("product_key", models.SlugField(max_length=80)),
                ("managed_key", models.SlugField(max_length=80)),
                ("catalog_version", models.PositiveIntegerField(default=1)),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="product_managed_roles", to="organization.organization")),
                ("role", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="product_management", to="iam.role")),
            ],
            options={"unique_together": {("organization", "product_key", "managed_key")}},
        ),
        migrations.CreateModel(
            name="ProductProvisioningEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("product_key", models.SlugField(max_length=80)),
                ("catalog_version", models.PositiveIntegerField()),
                ("service_client_id", models.CharField(max_length=120)),
                ("result", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="product_provisioning_events", to="organization.organization")),
            ],
        ),
    ]
