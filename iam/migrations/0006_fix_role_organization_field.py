# Migration untuk menambahkan kolom organization_id ke tabel iam_role jika belum ada

from django.db import migrations, models
import django.db.models.deletion


def _column_exists(schema_editor, table_name, column_name):
    """Return True when the target column already exists."""
    db_connection = schema_editor.connection

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
                return bool(result[0]) if result else False
            if db_connection.vendor == 'sqlite':
                cursor.execute("""
                    PRAGMA table_info(iam_role);
                """)
                columns = [row[1] for row in cursor.fetchall()]
                return 'organization_id' in columns
            return False
    except Exception:
        return False


def add_organization_column_if_missing(apps, schema_editor):
    """Add organization_id column only when absent to keep migration idempotent."""
    if _column_exists(schema_editor, "iam_role", "organization_id"):
        return

    db_connection = schema_editor.connection
    if db_connection.vendor == "postgresql":
        sql = (
            "ALTER TABLE iam_role "
            "ADD COLUMN organization_id uuid NULL "
            "REFERENCES organization_organization(id) "
            "DEFERRABLE INITIALLY DEFERRED"
        )
    elif db_connection.vendor == "sqlite":
        sql = "ALTER TABLE iam_role ADD COLUMN organization_id char(32) NULL"
    else:
        raise RuntimeError(f"Unsupported DB vendor for migration: {db_connection.vendor}")

    with db_connection.cursor() as cursor:
        cursor.execute(sql)


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0005_create_userpermission_table'),
        ('organization', '0001_initial'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    add_organization_column_if_missing,
                    reverse_code=migrations.RunPython.noop,
                )
            ],
            state_operations=[
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
            ],
        ),
    ]
