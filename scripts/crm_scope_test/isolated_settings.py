from datetime import timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SECRET_KEY = 'isolated-test-only-not-production'
DEBUG = False
USE_TZ = True
ROOT_URLCONF = 'isolated_urls'
ALLOWED_HOSTS = ['testserver']
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions',
                 'rest_framework', 'isolated_apps.AuthenticationConfig',
                 'isolated_apps.OrganizationConfig', 'isolated_apps.IamConfig']
AUTH_USER_MODEL = 'authentication.User'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
MIGRATION_MODULES = {'authentication': None, 'organization': None, 'iam': None}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
REST_FRAMEWORK = {'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework_simplejwt.authentication.JWTAuthentication'],
                 'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated']}
SIMPLE_JWT = {'ALGORITHM': 'RS256',
    'SIGNING_KEY': _key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
    'VERIFYING_KEY': _key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5), 'USER_ID_FIELD': 'id', 'USER_ID_CLAIM': 'user_id'}
SSO_ALLOWED_REDIRECT_URIS = []
SSO_AUTH_CODE_LIFETIME_SECONDS = 120
CRM_ARNASITE_TENANTS_URL = 'https://site.test/tenants/'
