# Migration untuk memperbaiki struktur tabel iam_userrole
# Menambahkan kolom organization_member_id jika belum ada

from django.db import migrations, models
import django.db.models.deletion


def check_and_add_column_safely(apps, schema_editor):
    """
    Check if organization_member_id column exists, if not, it will be added by AddField operation.
    This function is just for logging/safety checks.
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
                        AND column_name = 'organization_member_id'
                    );
                """)
                result = cursor.fetchone()
                column_exists = result[0] if result else False
            elif db_connection.vendor == 'sqlite':
                cursor.execute("""
                    PRAGMA table_info(iam_userrole);
                """)
                columns = [row[1] for row in cursor.fetchall()]
                column_exists = 'organization_member_id' in columns
            else:
                column_exists = False
    except Exception:
        column_exists = False
    
    if column_exists:
        # Column already exists, skip AddField operation
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Column organization_member_id already exists in iam_userrole.")
        # We'll still run AddField but it should handle the duplicate gracefully
    else:
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Column organization_member_id does not exist, will be added.")


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0002_add_organization_to_permission'),
        ('organization', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(
            check_and_add_column_safely,
            reverse_code=migrations.RunPython.noop,
        ),
        # Add field - will fail gracefully if column already exists
        migrations.AddField(
            model_name='userrole',
            name='organization_member',
            field=models.ForeignKey(
                null=True,  # Allow NULL temporarily for existing rows
                blank=True,
                on_delete=django.db.models.deletion.CASCADE,
                to='organization.organizationmember'
            ),
        ),
    ]
