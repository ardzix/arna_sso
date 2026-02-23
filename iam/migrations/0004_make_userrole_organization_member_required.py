# Migration untuk membuat kolom organization_member tidak nullable
# Menghapus rows yang memiliki NULL organization_member karena mereka tidak valid

from django.db import migrations, models
import django.db.models.deletion


def remove_invalid_userroles(apps, schema_editor):
    """
    Remove UserRole rows that have NULL organization_member.
    These are invalid and should be deleted.
    """
    UserRole = apps.get_model('iam', 'UserRole')
    
    # Delete rows with NULL organization_member
    deleted_count = UserRole.objects.filter(organization_member__isnull=True).delete()[0]
    
    if deleted_count > 0:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Deleted {deleted_count} invalid UserRole rows with NULL organization_member")


def reverse_remove_invalid_userroles(apps, schema_editor):
    """
    Reverse migration - nothing to do, we can't restore deleted rows
    """
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0003_fix_userrole_organization_member'),
        ('organization', '0001_initial'),
    ]

    operations = [
        # First, remove invalid rows
        migrations.RunPython(
            remove_invalid_userroles,
            reverse_code=reverse_remove_invalid_userroles,
        ),
        # Then, make the field required (not nullable)
        migrations.AlterField(
            model_name='userrole',
            name='organization_member',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to='organization.organizationmember'
            ),
        ),
    ]
