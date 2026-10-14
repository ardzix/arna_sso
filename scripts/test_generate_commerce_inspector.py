"""Isolated enrollment tests: only an in-memory ServiceAccount table, no runtime env."""
import importlib.util
from contextlib import redirect_stdout, redirect_stderr
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import django
from django.conf import settings

settings.configure(
    SECRET_KEY="synthetic-inspector-test-only",
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "authentication"],
    AUTH_USER_MODEL="authentication.User",
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    PASSWORD_HASHERS=["django.contrib.auth.hashers.PBKDF2PasswordHasher"],
    USE_TZ=True,
    Q_CLUSTER={"timeout": 30, "retry": 60},
)
django.setup()
from django.db import connection
from authentication.models import ServiceAccount

spec = importlib.util.spec_from_file_location("inspector_generator", Path(__file__).with_name("generate_commerce_inspector.py"))
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
with connection.schema_editor() as editor:
    editor.create_model(ServiceAccount)


class InspectorEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "commerce-inspector.env"
        # Only this table exists in the isolated harness; no related tables/data.
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM authentication_serviceaccount")

    def test_generated_pair_matches_hash_and_has_only_introspection_access(self):
        account, _ = generator.generate_credentials(generator.DEFAULT_CLIENT_ID, self.path)
        entries = dict(line.split("=", 1) for line in self.path.read_text().splitlines())
        self.assertEqual(set(entries), {"SSO_DEVICE_INTROSPECTION_CLIENT_ID", "SSO_DEVICE_INTROSPECTION_CLIENT_SECRET"})
        secret = entries["SSO_DEVICE_INTROSPECTION_CLIENT_SECRET"]
        self.assertGreaterEqual(len(secret), 64)
        self.assertTrue(account.check_client_secret(secret))
        self.assertNotEqual(account.client_secret_hash, secret)
        self.assertEqual(account.audiences, ["arna-sso-devices"])
        self.assertEqual(account.scopes, ["sso.device.introspect"])
        self.assertTrue(account.is_active)
        self.assertIsNone(account.organization_id)
        self.assertIsNone(account.tenant_id)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_existing_account_is_not_rotated_or_reactivated(self):
        account, _ = generator.generate_credentials(generator.DEFAULT_CLIENT_ID, self.path)
        account.is_active = False
        account.save(update_fields=["is_active"])
        old_hash = account.client_secret_hash
        other = self.path.with_name("other.env")
        with self.assertRaises(generator.EnrollmentError):
            generator.generate_credentials(generator.DEFAULT_CLIENT_ID, other)
        account.refresh_from_db()
        self.assertEqual(account.client_secret_hash, old_hash)
        self.assertFalse(account.is_active)
        self.assertFalse(other.exists())

    def test_existing_output_is_preserved_and_no_account_created(self):
        self.path.write_text("existing-content")
        with self.assertRaises(generator.EnrollmentError):
            generator.generate_credentials(generator.DEFAULT_CLIENT_ID, self.path)
        self.assertEqual(self.path.read_text(), "existing-content")
        self.assertFalse(ServiceAccount.objects.exists())

    def test_invalid_client_id_and_missing_parent_do_not_create_an_account(self):
        for client in ("bad\nENV=injected", "bad=id", "x" * 121):
            with self.assertRaises(generator.EnrollmentError):
                generator.generate_credentials(client, self.path)
        with self.assertRaises(generator.EnrollmentError):
            generator.generate_credentials(generator.DEFAULT_CLIENT_ID, self.path / "missing.env")
        self.assertFalse(ServiceAccount.objects.exists())
        self.assertFalse(self.path.exists())

    def test_database_failure_removes_output(self):
        with patch.object(ServiceAccount, "save", side_effect=RuntimeError("synthetic failure")):
            with self.assertRaises(RuntimeError):
                generator.generate_credentials(generator.DEFAULT_CLIENT_ID, self.path)
        self.assertFalse(self.path.exists())
        self.assertFalse(ServiceAccount.objects.exists())

    def test_file_flush_failure_rolls_back_account(self):
        with patch.object(generator.os, "fsync", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                generator.generate_credentials(generator.DEFAULT_CLIENT_ID, self.path)
        self.assertFalse(self.path.exists())
        self.assertFalse(ServiceAccount.objects.exists())

    def test_cli_omits_secret_from_stdout_and_stderr(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(generator.sys, "argv", ["generate_commerce_inspector.py", "--output", str(self.path)]):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(generator.main(), 0)
        secret = self.path.read_text().split("SSO_DEVICE_INTROSPECTION_CLIENT_SECRET=", 1)[1].strip()
        self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
        self.assertIn("Secret omitted", stdout.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
