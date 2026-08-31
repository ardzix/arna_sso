"""Drop legacy global unique constraints/indexes for IAM name columns."""

from django.db import migrations


def drop_legacy_global_name_indexes(apps, schema_editor):
    del apps
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute("ALTER TABLE iam_role DROP CONSTRAINT IF EXISTS iam_role_name_key")
    schema_editor.execute("DROP INDEX IF EXISTS iam_role_name_key")
    schema_editor.execute("ALTER TABLE iam_permission DROP CONSTRAINT IF EXISTS iam_permission_name_key")
    schema_editor.execute("DROP INDEX IF EXISTS iam_permission_name_key")


class Migration(migrations.Migration):
    """Remove stale DB-level unique indexes that block org-scoped duplicate names."""

    dependencies = [
        ("iam", "0008_drop_global_unique_name_constraints"),
    ]

    operations = [
        migrations.RunPython(drop_legacy_global_name_indexes, migrations.RunPython.noop),
    ]
