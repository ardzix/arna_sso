# Migration untuk menghapus kolom user_id dari tabel iam_userrole jika ada
# Kolom ini tidak seharusnya ada karena UserRole hanya memiliki organization_member

from django.db import migrations


def remove_user_id_column_if_exists(apps, schema_editor):
    """
    Remove user_id column from iam_userrole if it exists.
    This column should not exist - UserRole only has organization_member.
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
                        AND table_name = 'iam_userrole'
                        AND column_name = 'user_id'
                    );
                """)
                result = cursor.fetchone()
                column_exists = result[0] if result else False
            elif db_connection.vendor == 'sqlite':
                cursor.execute("""
                    PRAGMA table_info(iam_userrole);
                """)
                columns = [row[1] for row in cursor.fetchall()]
                column_exists = 'user_id' in columns
            else:
                column_exists = False
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Could not check if column exists: {str(e)}")
        column_exists = False
    
    if not column_exists:
        # Column doesn't exist, skip
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Column user_id does not exist in iam_userrole, skipping.")
        return
    
    # Column exists, remove it
    try:
        with db_connection.cursor() as cursor:
            if db_connection.vendor == 'postgresql':
                # Drop the column
                cursor.execute("ALTER TABLE iam_userrole DROP COLUMN IF EXISTS user_id;")
            elif db_connection.vendor == 'sqlite':
                # SQLite doesn't support DROP COLUMN directly, need to recreate table
                # This is more complex, skip for now
                import logging
                logger = logging.getLogger(__name__)
                logger.warning("SQLite doesn't support DROP COLUMN easily. Please handle manually.")
                return
        
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Removed user_id column from iam_userrole.")
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Could not remove user_id column: {str(e)}")
        # Don't raise - allow migration to continue


def reverse_remove_user_id_column(apps, schema_editor):
    """
    Reverse migration - cannot restore column without knowing its structure
    """
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0006_fix_role_organization_field'),
    ]

    operations = [
        migrations.RunPython(
            remove_user_id_column_if_exists,
            reverse_code=reverse_remove_user_id_column,
        ),
    ]
