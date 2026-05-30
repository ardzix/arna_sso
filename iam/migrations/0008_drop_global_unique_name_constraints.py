"""Drop legacy global unique constraints for IAM role/permission names."""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Ensure uniqueness is scoped by organization, not globally by name."""

    dependencies = [
        ("iam", "0007_remove_userrole_user_id"),
    ]

    operations = [
        migrations.AlterField(
            model_name="permission",
            name="name",
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name="role",
            name="name",
            field=models.CharField(max_length=255),
        ),
    ]
