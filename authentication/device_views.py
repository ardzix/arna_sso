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
from rest_framework.exceptions import APIException, PermissionDenied, ValidationError, NotFound
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from iam.models import UserPermission, UserRole
from organization.models import Organization, OrganizationMember
from audit_logging.models import AuditLog

from .models import DeviceAuthorizationGrant, DeviceRefreshCredential, DeviceRegistration
from .device_serializers import (DeviceAuthorizeSerializer, DeviceDecisionSerializer, DeviceReviewSerializer,
                                 DeviceRevokeSerializer, DeviceInventorySerializer, DeviceInventoryResponseSerializer,
                                 DeviceReviewResponseSerializer, DeviceRegistrationResponseSerializer, DeviceErrorSerializer,
                                 DeviceTokenSerializer, DeviceRefreshSerializer)
from .device_security import verify_tenant, verify_dpop
from .device_context import active_organization, active_context
from iam.effective import effective_access, STORAGE_PERMISSIONS


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


def _codes():
    # Exclude ambiguous characters so a human can type the code from a screen.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    user_code = "".join(secrets.choice(alphabet) for _ in range(8))
    return secrets.token_urlsafe(48), f"{user_code[:4]}-{user_code[4:]}"


def _device_access_token(registration, audience=None, subject_exp=None):
    if settings.SIMPLE_JWT["ALGORITHM"] != "RS256":
        raise APIException("Device credentials require RS256 signing configuration.")
    token = AccessToken()
    token.set_exp(lifetime=timedelta(minutes=settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES))
    if subject_exp is not None:
        token['exp'] = min(token['exp'], subject_exp)
    token["token_type"] = "device"
    token["iss"] = settings.DEVICE_TOKEN_ISSUER
    token["sub"] = str(registration.id)
    token["credential_version"] = registration.credential_version
    token["principal_type"] = "device"
    token["device_id"] = str(registration.id)
    token["client_id"] = registration.client_id
    token["org_id"] = str(registration.organization_id)
    token["organization_id"] = str(registration.organization_id)
    token["tenant_id"] = str(registration.tenant_id)
    token["aud"] = audience or registration.audience
    roles, permissions = effective_access(registration, registration.organization, device=True)
    token["roles"] = roles
    token["permissions"] = sorted(set(permissions) & STORAGE_PERMISSIONS) if audience == 'storage' else permissions
    token["is_owner"] = False
    token["scopes"] = token['permissions'] if audience == 'storage' else registration.scopes
    if registration.public_key_thumbprint:
        token["cnf"] = {"jkt": registration.public_key_thumbprint}
    return str(token)


def _issue_refresh(registration):
    raw = secrets.token_urlsafe(48)
    DeviceRefreshCredential.objects.create(
        token_hash=DeviceRefreshCredential.hash_secret(raw),
        registration=registration,
        credential_version=registration.credential_version,
        expires_at=timezone.now() + timedelta(days=settings.DEVICE_REFRESH_TOKEN_LIFETIME_DAYS),
    )
    return raw


def _can_manage_devices(user, organization):
    if not user.is_active:
        return False
    if organization.owner_id == user.id:
        return True
    membership = OrganizationMember.objects.filter(user=user, organization=organization).first()
    if not membership:
        return False
    direct = UserPermission.objects.filter(
        organization_member=membership,
        permissions__name="device.activate",
        permissions__organization=organization,
    ).exists()
    via_role = UserRole.objects.filter(
        organization_member=membership,
        role__permissions__name="device.activate",
        role__organization=organization,
        role__permissions__organization=organization,
    ).exists()
    return direct or via_role


def _error_detail(value):
    if isinstance(value, dict):
        return " ".join(f"{field}: {_error_detail(message)}" for field, message in value.items())
    if isinstance(value, list):
        return " ".join(_error_detail(message) for message in value)
    return str(value)


class DeviceAPIView(APIView):
    """Keep OAuth error codes while supplying human detail and a trace ID."""

    def handle_exception(self, exc):
        response = super().handle_exception(exc)
        if isinstance(exc, APIException):
            response.data = {"error": "invalid_request" if isinstance(exc, ValidationError) else exc.default_code,
                             "detail": _error_detail(exc.detail), "fields": exc.detail if isinstance(exc, ValidationError) else None}
        return response

    def finalize_response(self, request, response, *args, **kwargs):
        request_id = str(uuid.uuid4())
        if response.status_code >= 400 and isinstance(response.data, dict):
            descriptions = {
                "authorization_pending": "Waiting for an authorized operator to approve this device.",
                "slow_down": "Polling too quickly. Wait at least the returned interval before retrying.",
                "expired_token": "The pairing code expired. Start a new authorization request.",
                "access_denied": "Device authorization was denied, revoked or replaced. Pair again.",
                "invalid_grant": "The credential is unknown, expired, used, revoked or replaced. Pair again.",
                "unsupported_grant_type": "Use urn:ietf:params:oauth:grant-type:device_code.",
            }
            error = response.data.get("error", "invalid_request")
            response.data.setdefault("detail", descriptions.get(error, error))
            if " " in error:
                response.data["error"] = "invalid_request"
            response.data["request_id"] = request_id
        response["X-Request-ID"] = request_id
        response["Cache-Control"] = "no-store"
        return super().finalize_response(request, response, *args, **kwargs)


def _validated(serializer_class, data):
    serializer = serializer_class(data=data)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data


def _organization(user, organization_id=None):
    return active_organization(user, organization_id).organization


def _pending_grant(data, lock=False):
    query = DeviceAuthorizationGrant.objects
    if lock:
        query = query.select_for_update()
    grant = query.filter(user_code_hash=DeviceAuthorizationGrant.hash_secret(data["user_code"])).first()
    if not grant or grant.is_expired() or grant.consumed_at or grant.denied_at or grant.approved_at:
        raise ValidationError({"user_code": "This pairing code is unknown, expired or already decided. Start a new request."})
    if grant.requested_organization_id and grant.requested_organization_id != data.get("organization_id"):
        raise PermissionDenied("The selected organization does not match the organization requested by this device.")
    return grant


def _allowed_policy(registration):
    return (registration.audience in settings.DEVICE_ALLOWED_AUDIENCES
            and bool(registration.scopes)
            and set(registration.scopes).issubset(settings.DEVICE_AUDIENCE_SCOPES.get(registration.audience, [])))


def _registration_data(registration):
    return {"device_id": str(registration.pk), "client_id": registration.client_id,
            "device_name": registration.display_name, "organization_id": str(registration.organization_id),
            "tenant_id": str(registration.tenant_id), "audience": registration.audience,
            "scopes": registration.scopes, "is_active": registration.is_active,
            "credential_version": registration.credential_version,
            "key_bound": bool(registration.public_key_thumbprint),
            "approved_at": registration.approved_at, "last_seen_at": registration.last_seen_at}


class DeviceAuthorizeView(DeviceAPIView):
    """Start a tenant-bound device authorization request for a headless client."""
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "login_attempt"

    @swagger_auto_schema(
        operation_summary="Device authorization - start",
        operation_description=DEVICE_FLOW_GUIDE + "\n\n**This step:** creates a short-lived approval request and returns codes for the device and browser operator.",
        request_body=DeviceAuthorizeSerializer,
        responses={
            201: openapi.Response(description="Authorization request created", examples={"application/json": {"device_code": "opaque-secret", "user_code": "ABCD-EFGH", "verification_uri": "https://sso.arnatech.id/device/verify", "verification_uri_complete": "https://sso.arnatech.id/device/verify?user_code=ABCD-EFGH", "expires_in": 600, "interval": 5}}),
            400: "Missing/invalid fields or audience not allowed",
            429: "Too many authorization attempts",
        },
    )
    def post(self, request):
        data = _validated(DeviceAuthorizeSerializer, request.data)
        thumbprint = verify_dpop(request, data.get("public_key_thumbprint", ""))
        device_code, user_code = _codes()
        grant = DeviceAuthorizationGrant.objects.create(
            device_code_hash=DeviceAuthorizationGrant.hash_secret(device_code),
            user_code_hash=DeviceAuthorizationGrant.hash_secret(user_code.replace("-", "")),
            client_id=data["client_id"], device_name=data["device_name"],
            requested_organization_id=data.get("organization_id"),
            tenant_id=data.get("tenant_id"), audience=data["audience"], scopes=data["scopes"],
            public_key_thumbprint=thumbprint,
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


class DeviceReviewView(DeviceAPIView):
    """Review non-secret pairing details before making a decision."""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=DeviceReviewSerializer, operation_summary="Review a pending device request",
                         responses={200: DeviceReviewResponseSerializer, 400: DeviceErrorSerializer,
                                    403: DeviceErrorSerializer, 503: DeviceErrorSerializer})
    def post(self, request):
        data = _validated(DeviceReviewSerializer, request.data)
        organization = _organization(request.user, data.get("organization_id"))
        data['organization_id'] = organization.pk
        grant = _pending_grant(data)
        context = active_context(request.user, organization.pk)
        if grant.tenant_id and grant.tenant_id != context.active_tenant_id:
            raise PermissionDenied('This device request targets a different workspace. Switch workspace first.')
        organization = _organization(request.user, data["organization_id"])
        return Response({"client_id": grant.client_id, "device_name": grant.device_name,
                         "organization_id": str(organization.pk), "organization_name": organization.name,
                         "tenant_id": str(context.active_tenant_id), "audience": grant.audience, "scopes": grant.scopes,
                         "key_bound": bool(grant.public_key_thumbprint), "expires_at": grant.expires_at})


class DeviceVerificationView(DeviceAPIView):
    """Approve or deny a pending device authorization request from a trusted browser."""
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Device authorization - approve or deny",
        operation_description=DEVICE_FLOW_GUIDE + "\n\n**Who may call it:** owner or device.activate administrator of the active organization. Ownership is derived from the server-side active workspace; request IDs are optional compatibility hints and must match it.",
        request_body=DeviceDecisionSerializer,
        responses={200: openapi.Response(description="Decision recorded", examples={"application/json": {"status": "approved", "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "tenant_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}}), 400: DeviceErrorSerializer, 403: DeviceErrorSerializer, 409: DeviceErrorSerializer, 503: DeviceErrorSerializer},
    )
    @transaction.atomic
    def post(self, request):
        data = _validated(DeviceDecisionSerializer, request.data)
        organization = _organization(request.user, data.get("organization_id"))
        data['organization_id'] = organization.pk
        grant = _pending_grant(data, lock=True)
        context = active_context(request.user, organization.pk)
        if grant.tenant_id and grant.tenant_id != context.active_tenant_id:
            raise PermissionDenied('This device request targets a different workspace. Switch workspace first.')
        if data["action"] == "deny":
            grant.denied_at = timezone.now()
            grant.approved_by = request.user
            grant.save(update_fields=["denied_at", "approved_by"])
            AuditLog.objects.create(user=request.user, action="device_authorization_denied", metadata={"client_id": grant.client_id, "tenant_id": str(grant.tenant_id), "organization_id": str(organization.pk)})
            return Response({"status": "denied"})

        grant.tenant_id = context.active_tenant_id
        if not _allowed_policy(grant):
            raise ValidationError({"scopes": "Device scope policy changed. Start a new pairing request."})
        organization = _organization(request.user, data["organization_id"])
        if grant.is_expired():
            raise ValidationError({"user_code": "The pairing request expired during verification. Start again."})
        defaults = {
                "display_name": grant.device_name,
                "organization": organization,
                "tenant_id": grant.tenant_id,
                "audience": grant.audience,
                "scopes": grant.scopes,
                "public_key_thumbprint": grant.public_key_thumbprint,
                "is_active": True,
                "approved_by": request.user,
                "approved_at": timezone.now(),
            }
        registration, created = DeviceRegistration.objects.get_or_create(client_id=grant.client_id, defaults=defaults)
        registration = DeviceRegistration.objects.select_for_update().get(pk=registration.pk)
        if not created:
            if registration.is_active and registration.organization_id != organization.pk:
                return Response({"error": "device_already_registered", "detail": "This client_id is active in another organization. Its administrator must revoke it before reassignment."}, status=409)
            if registration.organization_id != organization.pk or registration.tenant_id != grant.tenant_id:
                registration.role_assignments.all().delete()
                from iam.models import DevicePermission
                DevicePermission.objects.filter(device=registration).delete()
            registration.credential_version += 1
            for field, value in defaults.items():
                setattr(registration, field, value)
            registration.save()
            DeviceRefreshCredential.objects.filter(registration=registration, revoked_at__isnull=True).update(revoked_at=timezone.now())
        grant.approved_registration = registration
        grant.approved_registration_version = registration.credential_version
        grant.approved_by = request.user
        grant.approved_at = timezone.now()
        grant.save(update_fields=["tenant_id", "approved_registration", "approved_registration_version", "approved_by", "approved_at"])
        AuditLog.objects.create(user=request.user, action="device_authorization_approved", metadata={"device_id": str(registration.id), "client_id": registration.client_id, "tenant_id": str(registration.tenant_id), "organization_id": str(registration.organization_id)})
        return Response({"status": "approved", **_registration_data(registration)})


class DeviceTokenView(DeviceAPIView):
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
        data = _validated(DeviceTokenSerializer, request.data)
        if data["grant_type"] != "urn:ietf:params:oauth:grant-type:device_code":
            return Response({"error": "unsupported_grant_type"}, status=status.HTTP_400_BAD_REQUEST)
        raw_code = data["device_code"]
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
            grant.interval_seconds += 5
            grant.save(update_fields=["interval_seconds"])
            return Response({"error": "slow_down", "interval": grant.interval_seconds}, status=status.HTTP_400_BAD_REQUEST)
        grant.last_polled_at = now
        grant.save(update_fields=["last_polled_at"])
        if not grant.approved_registration_id:
            if grant.approved_at:
                return Response({"error": "access_denied"}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": "authorization_pending"}, status=status.HTTP_400_BAD_REQUEST)
        registration = DeviceRegistration.objects.select_for_update().get(pk=grant.approved_registration_id)
        if (not registration.is_active or not _allowed_policy(registration)
                or grant.approved_registration_version != registration.credential_version):
            return Response({"error": "access_denied"}, status=status.HTTP_400_BAD_REQUEST)
        verify_dpop(request, registration.public_key_thumbprint)
        grant.consumed_at = now
        grant.save(update_fields=["consumed_at"])
        registration.last_seen_at = now
        registration.save(update_fields=["last_seen_at"])
        return Response({"access_token": _device_access_token(registration), "refresh_token": _issue_refresh(registration), "token_type": "DPoP" if registration.public_key_thumbprint else "Bearer", "expires_in": settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES * 60, **_registration_data(registration)})


class DeviceRefreshView(DeviceAPIView):
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
        raw = _validated(DeviceRefreshSerializer, request.data)["refresh_token"]
        candidate = DeviceRefreshCredential.objects.filter(token_hash=DeviceRefreshCredential.hash_secret(raw)).first()
        if not candidate:
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        # Lock registration first, consistently with approval and revocation.
        registration = DeviceRegistration.objects.select_for_update().filter(pk=candidate.registration_id).first()
        credential = DeviceRefreshCredential.objects.select_for_update().filter(pk=candidate.pk).first()
        if not registration or not credential:
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        credential.registration = registration
        if not credential.is_valid() or not _allowed_policy(registration):
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        verify_dpop(request, registration.public_key_thumbprint)
        credential.used_at = timezone.now()
        credential.save(update_fields=["used_at"])
        registration.last_seen_at = timezone.now()
        registration.save(update_fields=["last_seen_at"])
        return Response({"access_token": _device_access_token(registration), "refresh_token": _issue_refresh(registration), "token_type": "DPoP" if registration.public_key_thumbprint else "Bearer", "expires_in": settings.DEVICE_ACCESS_TOKEN_LIFETIME_MINUTES * 60, **_registration_data(registration)})


class DeviceRevokeView(DeviceAPIView):
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
        data = _validated(DeviceRevokeSerializer, request.data)
        registration = DeviceRegistration.objects.select_for_update().select_related("organization").filter(id=data["device_id"]).first()
        if not registration:
            return Response({"error": "Device not found."}, status=status.HTTP_404_NOT_FOUND)
        context = active_context(request.user)
        if registration.organization_id != context.organization_id or registration.tenant_id != context.active_tenant_id:
            return Response({"error": "You are not allowed to revoke this device."}, status=status.HTTP_403_FORBIDDEN)
        registration.is_active = False
        registration.credential_version += 1
        registration.save(update_fields=["is_active", "credential_version", "updated_at"])
        DeviceRefreshCredential.objects.filter(registration=registration, revoked_at__isnull=True).update(revoked_at=timezone.now())
        AuditLog.objects.create(user=request.user, action="device_revoked", metadata={"device_id": str(registration.id), "client_id": registration.client_id, "tenant_id": str(registration.tenant_id), "organization_id": str(registration.organization_id)})
        return Response(status=status.HTTP_204_NO_CONTENT)


class DeviceInventoryView(DeviceAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(query_serializer=DeviceInventorySerializer, operation_summary="List registered devices in an authorized organization",
                         responses={200: DeviceInventoryResponseSerializer, 400: DeviceErrorSerializer, 403: DeviceErrorSerializer})
    def get(self, request):
        data = _validated(DeviceInventorySerializer, request.query_params)
        context = active_context(request.user, data.get("organization_id"))
        devices = DeviceRegistration.objects.filter(organization=context.organization, tenant_id=context.active_tenant_id).order_by("-created_at", "pk")
        if data.get("tenant_id"):
            devices = devices.filter(tenant_id=data["tenant_id"])
        offset = (data["page"] - 1) * data["page_size"]
        return Response({"count": devices.count(), "page": data["page"], "page_size": data["page_size"],
                         "results": [_registration_data(device) for device in devices[offset:offset + data["page_size"]]]})


class DeviceDetailView(DeviceAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(query_serializer=DeviceInventorySerializer, operation_summary="Inspect a registered device",
                         responses={200: DeviceRegistrationResponseSerializer, 400: DeviceErrorSerializer,
                                    403: DeviceErrorSerializer, 404: DeviceErrorSerializer})
    def get(self, request, device_id):
        data = _validated(DeviceInventorySerializer, request.query_params)
        context = active_context(request.user, data.get("organization_id"))
        devices = DeviceRegistration.objects.filter(organization=context.organization, tenant_id=context.active_tenant_id, pk=device_id)
        if data.get("tenant_id"):
            devices = devices.filter(tenant_id=data["tenant_id"])
        registration = devices.first()
        if not registration:
            raise NotFound("Device not found in the selected organization/tenant.")
        return Response(_registration_data(registration))
