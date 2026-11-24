from django.db import migrations


def seed(apps, schema_editor):
    Permission = apps.get_model('iam', 'Permission')
    db = schema_editor.connection.alias
    for org in apps.get_model('organization', 'Organization').objects.using(db).iterator():
        for name in ('operations.read', 'operations.write', 'operations.manage'):
            Permission.objects.using(db).get_or_create(
                organization_id=org.pk, name=name,
                defaults={'description': 'Tenant business operations. No automatic user or role grants.'},
            )


class Migration(migrations.Migration):
    dependencies = [('iam', '0014_tenant_commerce_catalog')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
