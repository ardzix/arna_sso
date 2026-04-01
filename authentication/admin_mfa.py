import pyotp
from django import forms
from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class MFAAdminAuthenticationForm(AuthenticationForm):
    otp = forms.CharField(
        label=_("TOTP Code"),
        max_length=6,
        required=False,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "placeholder": "123456",
            }
        ),
        help_text=_("Required when MFA is enabled for this account."),
    )

    def clean(self):
        cleaned_data = super().clean()
        user = self.get_user()

        # Keep admin flow aligned with API flow:
        # require OTP only if MFA is configured for this user.
        if user and user.mfa_secret:
            otp = cleaned_data.get("otp")
            if not otp:
                raise ValidationError(_("TOTP code is required for this account."))

            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(otp, valid_window=1):
                raise ValidationError(_("Invalid TOTP code."))

        return cleaned_data


class MFAAdminSite(AdminSite):
    login_form = MFAAdminAuthenticationForm
    login_template = "admin/login.html"


def patch_admin_site():
    if admin.site.__class__ is not MFAAdminSite:
        admin.site.__class__ = MFAAdminSite

