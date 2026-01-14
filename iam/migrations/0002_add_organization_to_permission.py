# Generated manually for adding organization field to Permission
# Organization is REQUIRED - no global permissions allowed

from django.db import migrations, models
import django.db.models.deletion


def migrate_existing_permissions_to_org(apps, schema_editor):
    """
    Migrate existing permissions to a default organization.
    If no organizations exist, this will fail - which is expected for fresh installs.
    """
    Permission = apps.get_model('iam', 'Permission')
    Organization = apps.get_model('organization', 'Organization')
    
    # Get first organization as default (or create one if needed)
    # For production, you should handle this more carefully
    org = Organization.objects.first()
    
    if org:
        # Assign all existing permissions to first organization
        Permission.objects.filter(organization__isnull=True).update(organization=org)
    else:
        # If no organizations exist, delete all permissions (fresh install scenario)
        Permission.objects.filter(organization__isnull=True).delete()


def reverse_migrate_permissions(apps, schema_editor):
    """
    Reverse migration - set organization to NULL (but this won't work with new constraint)
    """
    # This is a one-way migration - cannot reverse safely
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0001_initial'),
        ('organization', '0001_initial'),
    ]

    operations = [
        # Remove unique constraint on name first
        migrations.AlterField(
            model_name='permission',
            name='name',
            field=models.CharField(max_length=255),
        ),
        # Add organization field (nullable first for data migration)
        migrations.AddField(
            model_name='permission',
            name='organization',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='permissions',
                to='organization.organization'
            ),
        ),
        # Migrate existing permissions to organization
        migrations.RunPython(
            migrate_existing_permissions_to_org,
            reverse_migrate_permissions,
        ),
        # Make organization required (no NULL allowed)
        migrations.AlterField(
            model_name='permission',
            name='organization',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='permissions',
                to='organization.organization'
            ),
        ),
        # Add unique_together constraint for (organization, name)
        migrations.AlterUniqueTogether(
            name='permission',
            unique_together={('organization', 'name')},
        ),
    ]

