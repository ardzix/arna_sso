"""Tenant-bound OAuth device authorization endpoints.

The device never receives a user's browser session.  It polls with an opaque
one-time device code, then receives a short access token and rotating opaque
refresh credential after a tenant member has approved it.
"""

import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from iam.models import UserPermission, UserRole
from organization.models import Organization, OrganizationMember
from audit_logging.models import AuditLog

from .models import DeviceAuthorizationGrant, DeviceRefreshCredential, DeviceRegistration


DEVICE_FLOW_GUIDE = """
Use this OAuth 2.0 Device Authorization flow for a CLI, smart device, agent, or
other device that cannot safely host a user login page. The device never handles
a user's password or browser session.

**End-to-end flow**

1. The device calls `POST /api/auth/device/authorize/` and shows `user_code`
   and `verification_uri_complete` to the operator.
2. In a trusted browser, an authenticated organization owner or member with
   `device.activate` opens the verification URI and calls
   `POST /api/auth/device/verification/` to approve or deny the request.
3. The device polls `POST /api/auth/device/token/` no faster than `interval`.
   It receives `authorization_pending` until approval, then receives its token pair once.
4. The device uses the access token as `Authorization: Bearer <access_token>`
   against the configured audience, and rotates its refresh token through
   `POST /api/auth/device/refresh/` before the access token expires.
5. An authorized tenant administrator revokes the device through
   `POST /api/auth/device/revoke/` when it is lost, retired, or compromised.

**Security rules:** store `device_code` and `refresh_token` only in secure device
storage; never put them in logs or URLs. A device code is one-time and expires.
The access token is tenant-bound (`tenant_id`, `org_id`), audience-bound (`aud`),
and contains only the approved scopes.
"""


DEVICE_AUTHORIZE_SCHEMA = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=["client_id", "device_name", "tenant_id", "audience", "scopes"],
    properties={
        "client_id": openapi.Schema(type=openapi.TYPE_STRING, example="arna-social-ai-worker"),
        "device_name": openapi.Schema(type=openapi.TYPE_STRING, example="Campaign Worker - production"),
        "tenant_id": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
        "audience": openapi.Schema(type=openapi.TYPE_STRING, example="arna_social_ai"),
        "scopes": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_STRING), example=["arna_social_ai.campaign.read", "arna_social_ai.report.upload"]),
        "public_key_thumbprint": openapi.Schema(type=openapi.TYPE_STRING, description="Optional RFC 7638 JWK thumbprint for proof-of-possession binding."),
    },
)


def _codes():
    # Exclude ambiguous characters so a human can type the code from a screen.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    user_code = "".join(secrets.choice(alphabet) for _ in range(8))
    return secrets.token_urlsafe(48), f"{user_code[:4]}-{user_code[4:]}"


def _normalized_scopes(value):
    if not isinstance(value, list) or not value or not all(isinstance(scope, str) and scope.strip() for scope in value):
        return None
    return sorted(set(scope.strip() for scope in value))


def _device_access_token(registration):
    token = AccessToken()
    token.set_exp(lifetime=timedelta(minutes=settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES))
    token["token_type"] = "device"
    token["principal_type"] = "device"
    token["device_id"] = str(registration.id)
    token["client_id"] = registration.client_id
    token["org_id"] = str(registration.organization_id)
    token["organization_id"] = str(registration.organization_id)
    token["tenant_id"] = str(registration.tenant_id)
    token["aud"] = registration.audience
    token["scopes"] = registration.scopes
    if registration.public_key_thumbprint:
        token["cnf"] = {"jkt": registration.public_key_thumbprint}
    return str(token)


def _issue_refresh(registration):
    raw = secrets.token_urlsafe(48)
    DeviceRefreshCredential.objects.create(
        token_hash=DeviceRefreshCredential.hash_secret(raw),
        registration=registration,
        expires_at=timezone.now() + timedelta(days=settings.DEVICE_REFRESH_TOKEN_LIFETIME_DAYS),
    )
    return raw


def _can_manage_devices(user, organization):
    if user.is_superuser or organization.owner_id == user.id:
        return True
    membership = OrganizationMember.objects.filter(user=user, organization=organization).first()
    if not membership:
        return False
    direct = UserPermission.objects.filter(
        organization_member=membership,
        permissions__name="device.activate",
    ).exists()
    via_role = UserRole.objects.filter(
        organization_member=membership,
        role__permissions__name="device.activate",
    ).exists()
    return direct or via_role


class DeviceAuthorizeView(APIView):
    """Start a tenant-bound device authorization request for a headless client."""
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "login_attempt"

    @swagger_auto_schema(
        operation_summary="Device authorization - start",
        operation_description=DEVICE_FLOW_GUIDE + "\n\n**This step:** creates a short-lived approval request and returns codes for the device and browser operator.",
        request_body=DEVICE_AUTHORIZE_SCHEMA,
        responses={
            201: openapi.Response(description="Authorization request created", examples={"application/json": {"device_code": "opaque-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://sso.arnatech.id/device/verify", "verification_uri_complete": "https://sso.arnatech.id/device/verify?user_code=ABCD-EFGH", "expires_in": 600, "interval": 5}}),
            400: "Missing/invalid fields or audience not allowed",
            429: "Too many authorization attempts",
        },
    )
    def post(self, request):
        client_id = str(request.data.get("client_id", "")).strip()
        device_name = str(request.data.get("device_name", "")).strip()
        tenant_id = str(request.data.get("tenant_id", "")).strip()
        audience = str(request.data.get("audience", "")).strip()
        scopes = _normalized_scopes(request.data.get("scopes"))
        if not client_id or not device_name or not tenant_id or not audience or not scopes:
            return Response({"error": "client_id, device_name, tenant_id, audience, and a non-empty scopes list are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uuid.UUID(tenant_id)
        except ValueError:
            return Response({"error": "tenant_id must be a UUID."}, status=status.HTTP_400_BAD_REQUEST)
        if settings.DEVICE_ALLOWED_AUDIENCES and audience not in settings.DEVICE_ALLOWED_AUDIENCES:
            return Response({"error": "The requested audience is not allowed for device credentials."}, status=status.HTTP_400_BAD_REQUEST)

        device_code, user_code = _codes()
        grant = DeviceAuthorizationGrant.objects.create(
            device_code_hash=DeviceAuthorizationGrant.hash_secret(device_code),
            user_code_hash=DeviceAuthorizationGrant.hash_secret(user_code.replace("-", "")),
            client_id=client_id,
            device_name=device_name,
            tenant_id=tenant_id,
            audience=audience,
            scopes=scopes,
            public_key_thumbprint=str(request.data.get("public_key_thumbprint", "")).strip(),
            expires_at=timezone.now() + timedelta(seconds=settings.DEVICE_AUTHORIZATION_LIFETIME_SECONDS),
            interval_seconds=settings.DEVICE_AUTHORIZATION_INTERVAL_SECONDS,
        )
        verification_uri = settings.DEVICE_VERIFICATION_URI.rstrip("/")
        return Response({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": f"{verification_uri}?user_code={user_code}",
            "expires_in": int((grant.expires_at - timezone.now()).total_seconds()),
            "interval": grant.interval_seconds,
        }, status=status.HTTP_201_CREATED)


class DeviceVerificationView(APIView):
    """Approve or deny a pending device authorization request from a trusted browser."""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Device authorization - approve or deny",
        operation_description=DEVICE_FLOW_GUIDE + "\n\n**Who may call it:** an authenticated organization owner, superuser, or organization member assigned the `device.activate` permission. The chosen `organization_id` becomes the device's organization context.",
        request_body=openapi.Schema(type=openapi.TYPE_OBJECT, required=["user_code", "organization_id", "action"], properties={"user_code": openapi.Schema(type=openapi.TYPE_STRING, example="ABCD-EFGH"), "organization_id": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID), "action": openapi.Schema(type=openapi.TYPE_STRING, enum=["approve", "deny"], example="approve")}),
        responses={200: openapi.Response(description="Decision recorded", examples={"application/json": {"status": "approved", "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "tenant_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}}), 400: "Expired, consumed, denied, or malformed request", 403: "Caller cannot manage devices in this organization"},
    )
    def post(self, request):
        user_code = str(request.data.get("user_code", "")).replace("-", "").strip().upper()
        organization_id = str(request.data.get("organization_id", "")).strip()
        action = str(request.data.get("action", "approve")).strip().lower()
        if not user_code or not organization_id or action not in {"approve", "deny"}:
            return Response({"error": "user_code, organization_id, and action (approve or deny) are required."}, status=status.HTTP_400_BAD_REQUEST)
        grant = DeviceAuthorizationGrant.objects.filter(user_code_hash=DeviceAuthorizationGrant.hash_secret(user_code)).first()
        if not grant or grant.is_expired() or grant.consumed_at or grant.denied_at:
            return Response({"error": "This device authorization request is no longer valid."}, status=status.HTTP_400_BAD_REQUEST)
        organization = Organization.objects.filter(id=organization_id).first()
        if not organization or not _can_manage_devices(request.user, organization):
            return Response({"error": "You are not allowed to approve devices for this organization."}, status=status.HTTP_403_FORBIDDEN)
        if action == "deny":
            grant.denied_at = timezone.now()
            grant.approved_by = request.user
            grant.save(update_fields=["denied_at", "approved_by"])
            AuditLog.objects.create(user=request.user, action="device_authorization_denied", metadata={"client_id": grant.client_id, "tenant_id": str(grant.tenant_id), "organization_id": organization_id})
            return Response({"status": "denied"})

        registration, _ = DeviceRegistration.objects.update_or_create(
            client_id=grant.client_id,
            defaults={
                "display_name": grant.device_name,
                "organization": organization,
                "tenant_id": grant.tenant_id,
                "audience": grant.audience,
                "scopes": grant.scopes,
                "public_key_thumbprint": grant.public_key_thumbprint,
                "is_active": True,
                "approved_by": request.user,
                "approved_at": timezone.now(),
            },
        )
        grant.approved_registration = registration
        grant.approved_by = request.user
        grant.approved_at = timezone.now()
        grant.save(update_fields=["approved_registration", "approved_by", "approved_at"])
        AuditLog.objects.create(user=request.user, action="device_authorization_approved", metadata={"device_id": str(registration.id), "client_id": registration.client_id, "tenant_id": str(registration.tenant_id), "organization_id": str(registration.organization_id)})
        return Response({"status": "approved", "device_id": str(registration.id), "tenant_id": str(registration.tenant_id)})


class DeviceTokenView(APIView):
    """Poll a pending device request and exchange an approved one for a device token pair."""
    permission_classes = [AllowAny]
    authentication_classes = []

    @swagger_auto_schema(
        operation_summary="Device authorization - poll for tokens",
        operation_description=DEVICE_FLOW_GUIDE + "\n\n**Polling behavior:** wait at least the returned `interval` before every retry. `authorization_pending` is expected before approval. On `slow_down`, increase the wait to the returned `interval`. A successful authorization is consumed and cannot be exchanged twice.",
        request_body=openapi.Schema(type=openapi.TYPE_OBJECT, required=["grant_type", "device_code"], properties={"grant_type": openapi.Schema(type=openapi.TYPE_STRING, enum=["urn:ietf:params:oauth:grant-type:device_code"]), "device_code": openapi.Schema(type=openapi.TYPE_STRING, description="Opaque device_code returned by authorize; never the human user_code.")}),
        responses={200: openapi.Response(description="Device token pair", examples={"application/json": {"access_token": "eyJ...", "refresh_token": "opaque-secret", "token_type": "Bearer", "expires_in": 300}}), 400: "authorization_pending, slow_down, access_denied, expired_token, invalid_grant, or unsupported_grant_type"},
    )
    @transaction.atomic
    def post(self, request):
        if request.data.get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code":
            return Response({"error": "unsupported_grant_type"}, status=status.HTTP_400_BAD_REQUEST)
        raw_code = str(request.data.get("device_code", ""))
        grant = DeviceAuthorizationGrant.objects.select_for_update().filter(device_code_hash=DeviceAuthorizationGrant.hash_secret(raw_code)).first()
        if not grant:
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        if grant.is_expired():
            return Response({"error": "expired_token"}, status=status.HTTP_400_BAD_REQUEST)
        if grant.denied_at:
            return Response({"error": "access_denied"}, status=status.HTTP_400_BAD_REQUEST)
        if grant.consumed_at:
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        now = timezone.now()
        if grant.last_polled_at and (now - grant.last_polled_at).total_seconds() < grant.interval_seconds:
            grant.interval_seconds += 1
            grant.save(update_fields=["interval_seconds"])
            return Response({"error": "slow_down", "interval": grant.interval_seconds}, status=status.HTTP_400_BAD_REQUEST)
        grant.last_polled_at = now
        grant.save(update_fields=["last_polled_at"])
        if not grant.approved_registration_id:
            return Response({"error": "authorization_pending"}, status=status.HTTP_400_BAD_REQUEST)
        registration = grant.approved_registration
        if not registration.is_active:
            return Response({"error": "access_denied"}, status=status.HTTP_400_BAD_REQUEST)
        grant.consumed_at = now
        grant.save(update_fields=["consumed_at"])
        registration.last_seen_at = now
        registration.save(update_fields=["last_seen_at"])
        return Response({"access_token": _device_access_token(registration), "refresh_token": _issue_refresh(registration), "token_type": "Bearer", "expires_in": settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES * 60})


class DeviceRefreshView(APIView):
    """Rotate an opaque device refresh credential into a new device token pair."""
    permission_classes = [AllowAny]
    authentication_classes = []

    @swagger_auto_schema(
        operation_summary="Device authorization - refresh tokens",
        operation_description=DEVICE_FLOW_GUIDE + "\n\n**Rotation:** every successful refresh invalidates the submitted refresh token and returns a new one. Persist the returned `refresh_token` atomically before discarding the previous value.",
        request_body=openapi.Schema(type=openapi.TYPE_OBJECT, required=["refresh_token"], properties={"refresh_token": openapi.Schema(type=openapi.TYPE_STRING, description="Current opaque device refresh token.")}),
        responses={200: openapi.Response(description="Rotated device token pair", examples={"application/json": {"access_token": "eyJ...", "refresh_token": "new-opaque-secret", "token_type": "Bearer", "expires_in": 300}}), 400: "invalid_grant - expired, revoked, used, or unknown refresh token"},
    )
    @transaction.atomic
    def post(self, request):
        raw = str(request.data.get("refresh_token", ""))
        credential = DeviceRefreshCredential.objects.select_for_update().select_related("registration", "registration__organization").filter(token_hash=DeviceRefreshCredential.hash_secret(raw)).first()
        if not credential or not credential.is_valid():
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        credential.used_at = timezone.now()
        credential.save(update_fields=["used_at"])
        registration = credential.registration
        registration.last_seen_at = timezone.now()
        registration.save(update_fields=["last_seen_at"])
        return Response({"access_token": _device_access_token(registration), "refresh_token": _issue_refresh(registration), "token_type": "Bearer", "expires_in": settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES * 60})


class DeviceRevokeView(APIView):
    """Deactivate a device registration and revoke all of its refresh credentials."""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Device authorization - revoke device",
        operation_description=DEVICE_FLOW_GUIDE + "\n\nUse this immediately for a lost, stolen, retired, or compromised device. The caller must be able to manage devices in the device organization. Existing access tokens remain valid only until their normal short expiry; all refresh credentials are revoked immediately.",
        request_body=openapi.Schema(type=openapi.TYPE_OBJECT, required=["device_id"], properties={"device_id": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID)}),
        responses={204: "Device revoked", 403: "Caller cannot revoke this device", 404: "Device not found"},
    )
    @transaction.atomic
    def post(self, request):
        registration = DeviceRegistration.objects.select_for_update().select_related("organization").filter(id=request.data.get("device_id")).first()
        if not registration:
            return Response({"error": "Device not found."}, status=status.HTTP_404_NOT_FOUND)
        if not _can_manage_devices(request.user, registration.organization):
            return Response({"error": "You are not allowed to revoke this device."}, status=status.HTTP_403_FORBIDDEN)
        registration.is_active = False
        registration.save(update_fields=["is_active"])
        DeviceRefreshCredential.objects.filter(registration=registration, revoked_at__isnull=True).update(revoked_at=timezone.now())
        AuditLog.objects.create(user=request.user, action="device_revoked", metadata={"device_id": str(registration.id), "client_id": registration.client_id, "tenant_id": str(registration.tenant_id), "organization_id": str(registration.organization_id)})
        return Response(status=status.HTTP_204_NO_CONTENT)
