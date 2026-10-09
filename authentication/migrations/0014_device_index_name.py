"""Reconcile existing overlong device index name with Django's model state."""
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("authentication", "0013_trustedregistration")]
    operations = [migrations.RenameIndex(
        model_name="deviceregistration", old_name="authentication_organiz_6bb37f_idx",
        new_name="authenticat_organiz_621900_idx",
    )]
