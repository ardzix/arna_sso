import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("authentication", "0012_serviceaccount_tenant")]
    operations = [
        migrations.CreateModel(name="TrustedRegistration", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("proof_hash", models.CharField(max_length=64)),
            ("payload_hash", models.CharField(max_length=64)),
            ("user_created", models.BooleanField()),
            ("created_at", models.DateTimeField(auto_now_add=True)),
            ("service", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="authentication.serviceaccount")),
            ("user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
        ]),
        migrations.AddConstraint(model_name="trustedregistration", constraint=models.UniqueConstraint(fields=("service", "proof_hash"), name="trusted_registration_service_proof")),
    ]
