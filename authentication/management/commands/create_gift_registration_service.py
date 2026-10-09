"""One-time, narrow service enrollment; does not rotate existing credentials."""
import sys

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from authentication.gift_registration import AUDIENCE, SCOPE
from authentication.models import ServiceAccount


class Command(BaseCommand):
    help = "Create the OLS gift registration principal using a secret supplied over stdin."

    def add_arguments(self, parser):
        parser.add_argument("--secret-stdin", action="store_true", required=True)

    def handle(self, *args, **options):
        raw_secret = sys.stdin.read(257).strip()
        if not 43 <= len(raw_secret) <= 256 or any(c.isspace() for c in raw_secret):
            raise CommandError("Supply a generated secret of 43–256 non-whitespace characters over stdin.")
        with transaction.atomic():
            if ServiceAccount.objects.filter(client_id="ols-wedding-gift-n8n").exists():
                raise CommandError("Service already exists; refuse silent credential rotation.")
            service = ServiceAccount(name="OLS Wedding Gift registration", client_id="ols-wedding-gift-n8n",
                                     scopes=[SCOPE], audiences=[AUDIENCE], is_active=True)
            service.set_client_secret(raw_secret)
            service.save()
        self.stdout.write(f"Created registration-only service {service.id}; secret omitted.")
