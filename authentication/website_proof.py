"""Restricted phone identity proof for the registered ArnaSite website client."""

from datetime import timedelta

from django.conf import settings
from rest_framework_simplejwt.tokens import Token

WEBSITE_CLIENT_ID = "arna-site-website"


class WebsiteCustomerProof(Token):
    # Ordinary SSO AccessToken/RefreshToken validators reject this token type.
    token_type = "website_customer"
    lifetime = timedelta(minutes=30)


def website_customer_proof(user):
    if not user.is_active or not user.phone_verified or not user.phone_number:
        raise ValueError("A verified, active phone identity is required.")
    proof = WebsiteCustomerProof()
    proof["sub"] = str(user.pk)
    proof["iss"] = settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id"
    proof["aud"] = settings.SIMPLE_JWT.get("AUDIENCE") or WEBSITE_CLIENT_ID
    proof["phone_number"] = user.phone_number
    proof["phone_verified"] = True
    proof["scope"] = "website.customer"
    return {
        "access": str(proof),
        "token_type": "Bearer",
        "expires_in": int(proof.lifetime.total_seconds()),
    }
