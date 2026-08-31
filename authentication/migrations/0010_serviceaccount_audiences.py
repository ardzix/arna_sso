from django.db import migrations, models


def seed_storage_audience(apps, schema_editor):
    del schema_editor
    ServiceAccount = apps.get_model("authentication", "ServiceAccount")
    ServiceAccount.objects.filter(audiences=[]).update(audiences=["storage"])


class Migration(migrations.Migration):
    dependencies = [("authentication", "0009_ssoallowedredirecturi")]

    operations = [
        migrations.AddField(
            model_name="serviceaccount",
            name="audiences",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.RunPython(seed_storage_audience, migrations.RunPython.noop),
    ]
