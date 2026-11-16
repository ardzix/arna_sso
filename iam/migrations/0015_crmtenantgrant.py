from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('iam', '0014_tenant_commerce_catalog'),
        ('organization', '0005_organizationmember_active_tenant_id'),
    ]
    operations = [
        migrations.CreateModel(
            name='CRMTenantGrant',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('tenant_id', models.UUIDField()),
                ('permissions', models.JSONField(default=list)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('organization_member', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='crm_tenant_grants', to='organization.organizationmember')),
            ],
        ),
        migrations.AddConstraint(
            model_name='crmtenantgrant',
            constraint=models.UniqueConstraint(fields=('organization_member', 'tenant_id'), name='unique_member_crm_tenant'),
        ),
    ]
