"""Only used by scripts/test_gift_registration.py, never production."""
from .settings import *  # noqa: F403
import os

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
if os.environ.get("GIFT_TEST_POSTGRES_HOST"):
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql", "NAME": "ols_gift_isolated",
        "HOST": os.environ["GIFT_TEST_POSTGRES_HOST"], "USER": "postgres",
        "PASSWORD": os.environ["GIFT_TEST_POSTGRES_PASSWORD"], "PORT": "5432",
    }}
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
ALLOWED_HOSTS = ["testserver", "localhost"]
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
Q_CLUSTER = {"name": "isolated-gift-tests", "sync": True, "orm": "default", "timeout": 90, "retry": 120}
