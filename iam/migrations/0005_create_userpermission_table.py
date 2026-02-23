# Migration untuk membuat tabel iam_userpermission jika belum ada
# Menangani kasus dimana migration 0001 tidak dijalankan dengan benar

from django.db import migrations, models
import django.db.models.deletion
import uuid


def create_userpermission_table_if_missing(apps, schema_editor):
    """
    Create UserPermission table if it doesn't exist.
    This handles cases where migration 0001 partially failed.
    """
    db_connection = schema_editor.connection
    
    # Check if table exists
    table_exists = False
    try:
        with db_connection.cursor() as cursor:
            if db_connection.vendor == 'postgresql':
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = 'iam_userpermission'
                    );
                """)
                table_exists = cursor.fetchone()[0]
            elif db_connection.vendor == 'sqlite':
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='iam_userpermission';
                """)
                table_exists = cursor.fetchone() is not None
            else:
                table_exists = False
    except Exception:
        table_exists = False
    
    if table_exists:
        # Table already exists, skip
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Table iam_userpermission already exists, skipping.")
        return
    
    # Table doesn't exist, create it
    try:
        UserPermission = apps.get_model('iam', 'UserPermission')
        schema_editor.create_model(UserPermission)
        
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Created iam_userpermission table.")
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Could not create UserPermission table: {str(e)}")
        raise


def remove_userpermission_table_if_exists(apps, schema_editor):
    """
    Remove UserPermission table if it exists (for reverse migration).
    """
    try:
        UserPermission = apps.get_model('iam', 'UserPermission')
        schema_editor.delete_model(UserPermission)
    except Exception:
        # If table doesn't exist, that's fine
        pass


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0004_make_userrole_organization_member_required'),
        ('organization', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(
            create_userpermission_table_if_missing,
            reverse_code=remove_userpermission_table_if_exists,
        ),
    ]
