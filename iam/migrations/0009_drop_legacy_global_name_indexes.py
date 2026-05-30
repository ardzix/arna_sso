"""Drop legacy global unique indexes for IAM name columns."""

from django.db import migrations


class Migration(migrations.Migration):
    """Remove stale DB-level unique indexes that block org-scoped duplicate names."""

    dependencies = [
        ("iam", "0008_drop_global_unique_name_constraints"),
    ]

    operations = [
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS iam_role_name_key;",
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS iam_permission_name_key;",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
