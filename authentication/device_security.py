"""Verified tenant ownership, device JWTs and optional DPoP key binding."""
import base64
import hashlib
import json
import secrets
import time
import uuid
from datetime import timedelta
from urllib.parse import urlsplit

import jwt
import requests
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.exceptions import APIException, AuthenticationFailed, PermissionDenied, ValidationError
from rest_framework_simplejwt.tokens import AccessToken

from .models import DeviceProofReplay, DeviceRegistration


class TenantVerificationUnavailable(APIException):
    status_code = 503
    default_code = "tenant_verification_unavailable"
    default_detail = "ArnaSite tenant verification is temporarily unavailable. Retry before approving."


def tenant_workspaces(user, organization):
    # Called only after verifying the operator's authority in this organization.
    # A short delegation carries no roles or permissions from another org.
    token = AccessToken.for_user(user)
    token.set_exp(lifetime=timedelta(minutes=1))
    token["iss"] = settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id"
    token["aud"] = "arna-site"
    token["org_id"] = str(organization.pk)
    token["roles"] = []
    token["permissions"] = []
    token["is_owner"] = organization.owner_id == user.pk
    url = settings.DEVICE_ARNASITE_TENANTS_URL
    parsed = urlsplit(url)
    local = settings.DEBUG and parsed.hostname in {"localhost", "127.0.0.1"}
    if (parsed.username or parsed.password or not parsed.hostname
            or (parsed.scheme != "https" and not (local and parsed.scheme == "http"))):
        raise TenantVerificationUnavailable()
    try:
        response = requests.get(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                                timeout=8, allow_redirects=False)
        if response.status_code != 200:
            raise TenantVerificationUnavailable()
        data = response.json()
        rows = data if isinstance(data, list) else data.get("results")
        if not isinstance(rows, list) or (isinstance(data, dict) and data.get("next")):
            raise TenantVerificationUnavailable()
        active = []
        for row in rows:
            if not isinstance(row, dict) or str(row.get("sso_organization_id")) != str(organization.pk):
                raise TenantVerificationUnavailable()
            row_id = uuid.UUID(str(row.get("tenant_id")))
            if row.get("is_active") is True:
                active.append({"tenant_id": row_id, "name": str(row.get("name") or row_id)})
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        raise TenantVerificationUnavailable() from exc
    return active


def verify_tenant(user, organization, tenant_id):
    if not any(row['tenant_id'] == tenant_id for row in tenant_workspaces(user, organization)):
        raise PermissionDenied("The requested tenant is not an active ArnaSite workspace of this organization.")


def _b64hash(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def verify_dpop(request, expected_thumbprint="", access_token=None):
    proof = request.headers.get("DPoP", "")
    if not proof:
        if expected_thumbprint:
            raise ValidationError({"DPoP": "A proof from the registered device key is required."})
        return ""
    try:
        if len(proof) > 8192:
            raise ValueError("Oversized proof")
        header = jwt.get_unverified_header(proof)
        jwk = header["jwk"]
        alg = header["alg"]
        if header.get("typ") != "dpop+jwt" or alg not in {"RS256", "ES256"} or header.get("crit"):
            raise ValueError("Unsupported proof")
        if not isinstance(jwk, dict) or any(key in jwk for key in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")):
            raise ValueError("Public asymmetric key required")
        if alg == "RS256" and jwk.get("kty") == "RSA":
            public = {key: jwk[key] for key in ("e", "kty", "n")}
        elif alg == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            public = {key: jwk[key] for key in ("crv", "kty", "x", "y")}
        else:
            raise ValueError("Key/algorithm mismatch")
        key = jwt.PyJWK.from_dict(public, algorithm=alg).key
        if alg == "RS256" and key.key_size < 2048:
            raise ValueError("Weak key")
        thumbprint = _b64hash(json.dumps(public, sort_keys=True, separators=(",", ":")).encode())
        if expected_thumbprint and not secrets.compare_digest(expected_thumbprint, thumbprint):
            raise ValueError("Wrong key")
        claims = jwt.decode(proof, key, algorithms=[alg], leeway=30,
                            options={"verify_aud": False, "require": ["iat", "jti", "htm", "htu"]})
        # Fixed trusted origin avoids proxy Host headers changing the proof target.
        expected_uri = settings.DEVICE_PUBLIC_ORIGIN + request.path
        if (claims["htm"] != request.method or claims["htu"] != expected_uri
                or type(claims["iat"]) is not int or not -30 <= time.time() - claims["iat"] <= 120
                or not isinstance(claims["jti"], str) or not 1 <= len(claims["jti"]) <= 200):
            raise ValueError("Invalid proof claims")
        if access_token is not None and not secrets.compare_digest(str(claims.get("ath", "")), _b64hash(access_token.encode())):
            raise ValueError("Access token hash mismatch")
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValidationError({"DPoP": "Invalid proof: check signature, key, method, URL, timestamp and token hash."}) from exc
    proof_hash = hashlib.sha256((thumbprint + "\n" + claims["jti"]).encode()).hexdigest()
    try:
        with transaction.atomic():
            DeviceProofReplay.objects.filter(expires_at__lte=timezone.now()).delete()
            DeviceProofReplay.objects.create(proof_hash=proof_hash, expires_at=timezone.now() + timedelta(minutes=5))
    except IntegrityError as exc:
        raise ValidationError({"DPoP": "This proof has already been used. Send a fresh proof."}) from exc
    return thumbprint


def device_token_registration(raw, audience):
    """Reject stale assignments even when the JWT signature/expiry is valid."""
    try:
        if settings.SIMPLE_JWT["ALGORITHM"] != "RS256":
            raise ValueError("RS256 required")
        claims = jwt.decode(raw, settings.SIMPLE_JWT["VERIFYING_KEY"], algorithms=["RS256"],
                            issuer=settings.DEVICE_TOKEN_ISSUER, audience=audience,
                            options={"require": ["iss", "aud", "exp", "iat", "jti", "sub", "token_type",
                                                 "device_id", "client_id", "organization_id", "org_id", "tenant_id",
                                                 "scopes", "credential_version"]})
        registration = DeviceRegistration.objects.get(pk=uuid.UUID(claims["device_id"]), is_active=True)
        from iam.effective import effective_access, RESOURCE_PERMISSIONS
        roles, permissions = effective_access(registration, registration.organization, device=True)
        resource_scopes = sorted(set(permissions) & RESOURCE_PERMISSIONS.get(claims['aud'], set()))
        resource_token = claims['aud'] in RESOURCE_PERMISSIONS and registration.audience != claims['aud']
        expected_scopes = resource_scopes if resource_token else registration.scopes
        if (claims["token_type"] != "device" or claims.get("principal_type") != "device"
                or claims["sub"] != str(registration.pk) or claims["client_id"] != registration.client_id
                or claims["organization_id"] != str(registration.organization_id)
                or claims["org_id"] != str(registration.organization_id)
                or claims["tenant_id"] != str(registration.tenant_id)
                or (claims["aud"] != registration.audience and not resource_token)
                or claims["scopes"] != expected_scopes
                or (resource_token and (not resource_scopes or claims.get('permissions') != resource_scopes))
                or (claims['aud'] == 'arna-commerce' and (registration.audience != 'photobooth-api'
                    or claims.get('source_audience') != registration.audience or claims.get('is_owner') is not False))
                or registration.audience not in settings.DEVICE_ALLOWED_AUDIENCES
                or not set(registration.scopes).issubset(settings.DEVICE_AUDIENCE_SCOPES.get(registration.audience, []))
                or type(claims["credential_version"]) is not int
                or claims["credential_version"] != registration.credential_version
                or claims.get("cnf", {}).get("jkt", "") != registration.public_key_thumbprint):
            raise ValueError("Assignment changed")
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, DeviceRegistration.DoesNotExist) as exc:
        raise AuthenticationFailed("Invalid, expired, revoked or replaced device token. Pair the device again.") from exc
    return registration, claims
