from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("authentication", "0011_device_identity")]
    operations = [
        migrations.AddField(
            model_name="serviceaccount",
            name="tenant_id",
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddConstraint(
            model_name="serviceaccount",
            constraint=models.CheckConstraint(
                check=models.Q(tenant_id__isnull=True) | models.Q(organization_id__isnull=False),
                name="service_tenant_requires_org",
            ),
        ),
    ]
