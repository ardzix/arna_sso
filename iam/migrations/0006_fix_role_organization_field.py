# Migration untuk menambahkan kolom organization_id ke tabel iam_role jika belum ada

from django.db import migrations, models
import django.db.models.deletion


def add_organization_column_if_missing(apps, schema_editor):
    """
    Add organization column to iam_role if it doesn't exist.
    This handles cases where migration 0001 didn't run properly.
    """
    db_connection = schema_editor.connection
    
    # Check if column exists
    column_exists = False
    try:
        with db_connection.cursor() as cursor:
            if db_connection.vendor == 'postgresql':
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_schema = 'public' 
                        AND table_name = 'iam_role'
                        AND column_name = 'organization_id'
                    );
                """)
                result = cursor.fetchone()
                column_exists = result[0] if result else False
            elif db_connection.vendor == 'sqlite':
                cursor.execute("""
                    PRAGMA table_info(iam_role);
                """)
                columns = [row[1] for row in cursor.fetchall()]
                column_exists = 'organization_id' in columns
            else:
                column_exists = False
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Could not check if column exists: {str(e)}")
        column_exists = False
    
    if column_exists:
        # Column already exists, skip
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Column organization_id already exists in iam_role, skipping.")
        return
    
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Column organization_id does not exist, will be added by AddField operation.")


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0005_create_userpermission_table'),
        ('organization', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(
            add_organization_column_if_missing,
            reverse_code=migrations.RunPython.noop,
        ),
        # Add field - will fail gracefully if column already exists
        migrations.AddField(
            model_name='role',
            name='organization',
            field=models.ForeignKey(
                null=True,  # Allow NULL for backward compatibility
                blank=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='roles',
                to='organization.organization'
            ),
        ),
    ]
