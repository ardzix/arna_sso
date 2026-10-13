from django.db import migrations


def seed(apps, schema_editor):
    Organization = apps.get_model('organization', 'Organization')
    Permission = apps.get_model('iam', 'Permission')
    names = ('storage.files.read', 'storage.files.create', 'storage.files.update',
             'storage.files.delete', 'storage.files.share', 'storage.folders.create')
    for org_id in Organization.objects.values_list('pk', flat=True).iterator():
        for name in names:
            Permission.objects.get_or_create(organization_id=org_id, name=name,
                defaults={'description': 'File Manager permission for human and device principals.'})


class Migration(migrations.Migration):
    dependencies = [('iam', '0011_devicepermission_devicerole_and_more')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
