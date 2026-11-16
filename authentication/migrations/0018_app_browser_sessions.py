import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


CALLBACKS = {
    "arna-account": ["https://account.arnatech.id/api/auth/callback"],
    "arnasite-dashboard": ["https://www.bisnisnaikkelas.com/api/auth/callback", "https://bisnisnaikkelas.com/api/auth/callback"],
    "arnaos": ["https://company.arnatech.id/api/auth/callback"],
    "arna-clockin": ["https://clockin.arnatech.id/api/auth/callback"],
}


def register_callbacks(apps, schema_editor):
    redirect = apps.get_model("authentication", "SSOAllowedRedirectURI")
    for client_id, urls in CALLBACKS.items():
        for url in urls:
            redirect.objects.get_or_create(client_id=client_id, redirect_uri=url, defaults={"is_active": True})


class Migration(migrations.Migration):
    dependencies = [("authentication", "0017_shared_mfa_state")]
    operations = [
        migrations.AddField(model_name="ssoauthorizationcode", name="browser_session_key",
                            field=models.CharField(blank=True, default="", max_length=40)),
        migrations.CreateModel(name="SSOAppSession", fields=[
            ("credential_hash", models.CharField(max_length=64, primary_key=True, serialize=False)),
            ("client_id", models.CharField(max_length=120)),
            ("browser_session_key", models.CharField(max_length=40)),
            ("created_at", models.DateTimeField(auto_now_add=True)),
            ("expires_at", models.DateTimeField(db_index=True)),
            ("revoked_at", models.DateTimeField(blank=True, null=True)),
            ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
        ]),
        migrations.RunPython(register_callbacks, migrations.RunPython.noop),
    ]
