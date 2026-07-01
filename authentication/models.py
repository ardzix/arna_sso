import uuid
import hashlib
import secrets
import pyotp
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from urllib.parse import urlparse

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    mfa_enabled = models.BooleanField(default=False)
    profile_data = models.JSONField(null=True, blank=True)
    mfa_secret = models.CharField(max_length=32, null=True, blank=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expiration = models.DateTimeField(null=True, blank=True)
    last_otp_sent = models.DateTimeField(null=True, blank=True)  # Tracks last OTP sent time
    phone_number = models.CharField(max_length=20, null=True, blank=True, unique=True)
    phone_verified = models.BooleanField(default=False)
    pending_phone = models.CharField(max_length=20, null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    def get_by_natural_key(self, email):
        return self.get(email=email)

    def generate_mfa_secret(self):
        """Generate a new MFA secret for the user."""
        self.mfa_secret = pyotp.random_base32()
        self.mfa_enabled = True
        self.save()

    def verify_mfa(self, token):
        """Verify the provided MFA token."""
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token)

    @property
    def username(self):
        """
        Alias for email, required by some third-party apps (like django-passkeys)
        that expect a 'username' attribute.
        """
        return self.email

    def get_full_name(self):
        """Return the email as the full name."""
        return self.email

    def get_short_name(self):
        """Return the email as the short name."""
        return self.email


class CorsAllowedOrigin(models.Model):
    origin = models.CharField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    notes = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("origin",)
        verbose_name = "CORS Allowed Origin"
        verbose_name_plural = "CORS Allowed Origins"

    @staticmethod
    def _is_valid_origin(value: str) -> bool:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            return False
        if not parsed.netloc:
            return False
        if parsed.path not in {"", "/"}:
            return False
        if parsed.params or parsed.query or parsed.fragment:
            return False
        return True

    def clean(self):
        origin = (self.origin or "").strip().rstrip("/")
        if not self._is_valid_origin(origin):
            raise ValidationError(
                {
                    "origin": (
                        "Invalid origin format. Use scheme + host only, e.g. "
                        "'https://app.example.com' (optional port allowed)."
                    )
                }
            )
        self.origin = origin

    def save(self, *args, **kwargs):
        self.origin = (self.origin or "").strip().rstrip("/")
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.origin} ({'active' if self.is_active else 'inactive'})"


class ServiceAccount(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    client_id = models.CharField(max_length=120, unique=True)
    client_secret_hash = models.CharField(max_length=255)
    organization_id = models.UUIDField(null=True, blank=True)
    scopes = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_client_secret(self, raw_secret):
        self.client_secret_hash = make_password(raw_secret)

    def check_client_secret(self, raw_secret):
        return check_password(raw_secret, self.client_secret_hash)

    def __str__(self):
        return self.name


class SSOAuthorizationCode(models.Model):
    CODE_CHALLENGE_METHODS = (
        ("S256", "S256"),
        ("plain", "plain"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code_hash = models.CharField(max_length=64, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sso_auth_codes")
    client_id = models.CharField(max_length=120)
    redirect_uri = models.URLField(max_length=500)
    code_challenge = models.CharField(max_length=128)
    code_challenge_method = models.CharField(
        max_length=10,
        choices=CODE_CHALLENGE_METHODS,
        default="S256",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("client_id", "redirect_uri")),
            models.Index(fields=("expires_at",)),
        ]

    @staticmethod
    def hash_code(code):
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @classmethod
    def create_for_user(
        cls,
        *,
        user,
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        expires_at,
    ):
        code = secrets.token_urlsafe(48)
        instance = cls.objects.create(
            code_hash=cls.hash_code(code),
            user=user,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at,
        )
        return code, instance

    def is_expired(self):
        return self.expires_at <= timezone.now()

    def is_used(self):
        return self.used_at is not None

    def mark_used(self):
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])

    def __str__(self):
        return f"{self.client_id} -> {self.redirect_uri}"
