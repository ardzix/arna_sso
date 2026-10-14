from django.db import migrations


def seed(apps, schema_editor):
    Permission = apps.get_model('iam', 'Permission')
    for org in apps.get_model('organization', 'Organization').objects.using(schema_editor.connection.alias).iterator():
        for name in ('commerce.orders.read', 'commerce.orders.write', 'commerce.payments.create'):
            Permission.objects.using(schema_editor.connection.alias).get_or_create(
                organization_id=org.pk, name=name,
                defaults={'description': 'Tenant photobooth checkout permission; does not grant payment event processing.'})


class Migration(migrations.Migration):
    dependencies = [('iam', '0012_storage_permission_catalog')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
