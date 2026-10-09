"""Isolated tests: synthetic RSA keys and temporary PostgreSQL, no production env.

The legacy IAM migration chain requires PostgreSQL. Use test_gift_remote.py
or configure GIFT_TEST_POSTGRES_HOST/PASSWORD for a disposable test server.
"""
import os
from pathlib import Path
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
os.environ["DJANGO_SETTINGS_MODULE"] = "sso_service.gift_test_settings"
with tempfile.TemporaryDirectory(prefix="ols-gift-sso-test-") as folder:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = Path(folder) / "private.pem"
    public = Path(folder) / "public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os.environ.update(SECRET_KEY="isolated-synthetic-test-only", USE_SQLITE="true",
                      JWT_PRIVATE_KEY_PATH=str(private), JWT_PUBLIC_KEY_PATH=str(public),
                      JWT_ISSUER="https://sso.arnatech.id", JWT_AUDIENCE="", DEBUG="false")
    import django
    django.setup()
    from django.core.management import call_command
    call_command("check")
    # Health routes and environment delivery are part of this exact release.
    from django.test import Client
    assert Client().get('/health/live', HTTP_HOST='localhost').json() == {'status': 'ok'}
    call_command("makemigrations", check=True, dry_run=True)
    call_command("test", "authentication.tests.test_gift_registration", "authentication.tests.test_website_service",
                 "authentication.tests.test_website_proof", "authentication.tests.test_wa_otp_throttling", verbosity=2)
