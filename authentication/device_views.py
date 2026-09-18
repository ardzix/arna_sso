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

from iam.models import UserPermission, UserRole
from organization.models import Organization, OrganizationMember
from audit_logging.models import AuditLog

from .models import DeviceAuthorizationGrant, DeviceRefreshCredential, DeviceRegistration


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
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "login_attempt"

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
    permission_classes = [IsAuthenticated]

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
    permission_classes = [AllowAny]
    authentication_classes = []

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
    permission_classes = [AllowAny]
    authentication_classes = []

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
    permission_classes = [IsAuthenticated]

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
