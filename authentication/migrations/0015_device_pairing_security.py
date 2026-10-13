from django.db import migrations, models
from django.utils import timezone


def invalidate_unverified_pairings(apps, schema_editor):
    # Legacy assignments did not verify tenant ownership or device key possession.
    # They must go through the new approval flow; never silently backfill trust.
    alias = schema_editor.connection.alias
    apps.get_model("authentication", "DeviceRegistration").objects.using(alias).update(is_active=False, credential_version=2)
    apps.get_model("authentication", "DeviceRefreshCredential").objects.using(alias).filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
    apps.get_model("authentication", "DeviceAuthorizationGrant").objects.using(alias).filter(consumed_at__isnull=True, denied_at__isnull=True).update(denied_at=timezone.now())


class Migration(migrations.Migration):
    dependencies = [("authentication", "0014_device_index_name")]
    operations = [
        migrations.AddField(model_name="deviceregistration", name="credential_version", field=models.PositiveIntegerField(default=1)),
        migrations.AddField(model_name="deviceauthorizationgrant", name="requested_organization_id", field=models.UUIDField(blank=True, null=True)),
        migrations.AddField(model_name="deviceauthorizationgrant", name="approved_registration_version", field=models.PositiveIntegerField(blank=True, null=True)),
        migrations.AddField(model_name="devicerefreshcredential", name="credential_version", field=models.PositiveIntegerField(default=1)),
        migrations.CreateModel(name="DeviceProofReplay", fields=[
            ("proof_hash", models.CharField(max_length=64, primary_key=True, serialize=False)),
            ("expires_at", models.DateTimeField(db_index=True)),
        ]),
        migrations.RunPython(invalidate_unverified_pairings, migrations.RunPython.noop),
    ]
