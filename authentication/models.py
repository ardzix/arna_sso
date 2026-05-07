import uuid
import pyotp
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
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
