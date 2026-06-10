import secrets
import uuid

from django.core.management.base import BaseCommand, CommandError

from authentication.models import ServiceAccount


class Command(BaseCommand):
    help = "Create or rotate an SSO service account client secret."

    def add_arguments(self, parser):
        parser.add_argument("client_id")
        parser.add_argument("--name", default="")
        parser.add_argument("--client-secret", default="")
        parser.add_argument("--organization-id", default="")
        parser.add_argument("--scope", action="append", dest="scopes", default=[])

    def handle(self, *args, **options):
        organization_id = options["organization_id"] or None
        if organization_id:
            try:
                organization_id = uuid.UUID(organization_id)
            except ValueError as exc:
                raise CommandError("organization-id must be a UUID.") from exc
        raw_secret = options["client_secret"] or secrets.token_urlsafe(48)
        service, created = ServiceAccount.objects.get_or_create(
            client_id=options["client_id"],
            defaults={"name": options["name"] or options["client_id"]},
        )
        service.name = options["name"] or service.name
        service.organization_id = organization_id
        service.scopes = options["scopes"]
        service.is_active = True
        service.set_client_secret(raw_secret)
        service.save()
        action = "Created" if created else "Rotated"
        self.stdout.write(self.style.SUCCESS(f"{action} service account {service.client_id} ({service.id})"))
        self.stdout.write(f"Client secret: {raw_secret}")
