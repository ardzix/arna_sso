from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('authentication', '0018_app_browser_sessions')]
    operations = [
        migrations.AddField(model_name='ssoauthorizationcode', name='crm_context',
                            field=models.JSONField(default=dict, blank=True)),
        migrations.AddField(model_name='ssoauthorizationcode', name='credential_expires_at',
                            field=models.BigIntegerField(null=True, blank=True)),
    ]
