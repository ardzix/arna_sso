#!/usr/bin/env python3
"""Enroll a backend-only Commerce inspector; write credentials to a private file.

Run inside the configured Arna SSO runtime. This never rotates an existing client,
prints a secret, assigns tenant roles, runs migrations, or changes Commerce env.
The file contains only two env entries, not the complete Commerce configuration.
"""
import argparse
import os
from pathlib import Path
import re
import secrets
import sys

AUDIENCE = "arna-sso-devices"
SCOPE = "sso.device.introspect"
DEFAULT_CLIENT_ID = "arna-commerce-device-inspector"


class EnrollmentError(Exception):
    pass


def generate_credentials(client_id, output):
    from django.db import transaction
    from authentication.models import ServiceAccount

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", client_id):
        raise EnrollmentError("Client ID must contain 1-120 ASCII letters, digits, dots, underscores or hyphens.")
    output = Path(output).absolute()
    if not output.parent.is_dir():
        raise EnrollmentError("Output parent directory must already exist.")
    created_file = False
    try:
        with transaction.atomic():
            if ServiceAccount.objects.filter(client_id=client_id).exists():
                raise EnrollmentError("Client ID already exists; no credential was changed. Use the existing secret or choose a new --client-id.")
            # O_EXCL refuses existing paths, including symlinks. No secret goes to stdout.
            try:
                descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError as exc:
                raise EnrollmentError("Output already exists; refusing to overwrite it.") from exc
            created_file = True
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                secret = secrets.token_urlsafe(48)
                account = ServiceAccount(
                    name="Commerce device introspection", client_id=client_id,
                    organization_id=None, tenant_id=None,
                    audiences=[AUDIENCE], scopes=[SCOPE], is_active=True,
                )
                account.set_client_secret(secret)
                account.full_clean()
                account.save(force_insert=True)
                stream.write(f"SSO_DEVICE_INTROSPECTION_CLIENT_ID={client_id}\n")
                stream.write(f"SSO_DEVICE_INTROSPECTION_CLIENT_SECRET={secret}\n")
                stream.flush()
                os.fsync(stream.fileno())
        return account, output
    except BaseException:
        # Also remove the file if DB commit fails; preserve all pre-existing files.
        if created_file:
            output.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--output", required=True, type=Path, help="New private file for the two Commerce env entries.")
    args = parser.parse_args()
    # Supports either a saved script in scripts/ or python - < script.py inside SSO.
    source = globals().get("__file__", "<stdin>")
    root = Path.cwd() if source == "<stdin>" else Path(source).resolve().parents[1]
    sys.path.insert(0, str(root))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sso_service.settings")
    try:
        import django
        django.setup()
        account, output = generate_credentials(args.client_id, args.output)
    except EnrollmentError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("Enrollment failed. Run inside a configured SSO runtime with migrated ServiceAccount tables and a writable output directory. No credential values are printed.", file=sys.stderr)
        return 1
    print(f"Created {account.client_id} ({account.pk}).")
    print(f"Audience: {AUDIENCE}; scope: {SCOPE}.")
    print(f"Credential file: {output}. Secret omitted from console output.")
    print("Merge its two entries into the existing Jenkins arna-commerce-env credential; preserve all other settings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
