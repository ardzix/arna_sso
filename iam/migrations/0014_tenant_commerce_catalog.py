from django.db import migrations


def seed(apps, schema_editor):
    Permission = apps.get_model('iam', 'Permission')
    db = schema_editor.connection.alias
    for org in apps.get_model('organization', 'Organization').objects.using(db).iterator():
        for name in ('commerce.catalog.read', 'commerce.catalog.write', 'commerce.catalog.delete'):
            Permission.objects.using(db).get_or_create(organization_id=org.pk, name=name,
                defaults={'description': 'Manage only the active tenant Commerce catalog; no platform administration.'})


class Migration(migrations.Migration):
    dependencies = [('iam', '0013_photobooth_commerce_permissions')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
