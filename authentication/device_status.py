"""Device self-status and narrowly authorized backend token introspection."""
import uuid
from dataclasses import dataclass

import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from .device_security import device_token_registration, verify_dpop
from .device_serializers import DeviceIntrospectionSerializer, DeviceStatusResponseSerializer, DeviceErrorSerializer
from .device_views import DeviceAPIView, _validated, _registration_data
from .models import ServiceAccount
from iam.effective import RESOURCE_PERMISSIONS

INTROSPECTION_AUDIENCE = "arna-sso-devices"
INTROSPECTION_SCOPE = "sso.device.introspect"


@dataclass
class DeviceServicePrincipal:
    service: ServiceAccount
    is_authenticated: bool = True

    @property
    def pk(self):
        return self.service.pk


class DeviceServiceAuthentication(BaseAuthentication):
    def authenticate_header(self, request):
        return "Bearer"

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header:
            return None
        try:
            if len(header) != 2 or header[0].lower() != b"bearer" or settings.SIMPLE_JWT["ALGORITHM"] != "RS256":
                raise ValueError("Invalid authorization")
            claims = jwt.decode(header[1], settings.SIMPLE_JWT["VERIFYING_KEY"], algorithms=["RS256"],
                                issuer=settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id",
                                audience=INTROSPECTION_AUDIENCE,
                                options={"require": ["exp", "iat", "iss", "aud", "jti", "token_type", "service_id", "client_id"]})
            service = ServiceAccount.objects.get(pk=uuid.UUID(claims["service_id"]), is_active=True)
            if (claims["token_type"] != "service" or claims.get("principal_type") != "service"
                    or claims["aud"] != INTROSPECTION_AUDIENCE or claims.get("scopes") != [INTROSPECTION_SCOPE]
                    or service.scopes != [INTROSPECTION_SCOPE] or service.audiences != [INTROSPECTION_AUDIENCE]
                    or service.client_id != claims["client_id"]
                    or not 0 < claims["exp"] - claims["iat"] <= 300
                    or claims.get("org_id") != (str(service.organization_id) if service.organization_id else None)
                    or claims.get("tenant_id") != (str(service.tenant_id) if service.tenant_id else None)):
                raise ValueError("Service permissions changed")
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, ServiceAccount.DoesNotExist) as exc:
            raise AuthenticationFailed("Invalid or revoked device introspection service token.") from exc
        return DeviceServicePrincipal(service), claims


class DeviceStatusView(DeviceAPIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get_authenticate_header(self, request):
        return "Bearer"

    @swagger_auto_schema(operation_summary="Check this device's current registration using its device token",
                         responses={200: DeviceStatusResponseSerializer, 400: DeviceErrorSerializer, 401: DeviceErrorSerializer})
    def get(self, request):
        header = get_authorization_header(request).split()
        if len(header) != 2 or header[0].lower() not in {b"bearer", b"dpop"}:
            raise AuthenticationFailed("A device access token is required.")
        try:
            raw = header[1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthenticationFailed("Invalid device authorization.") from exc
        registration, _ = device_token_registration(raw, settings.DEVICE_ALLOWED_AUDIENCES + list(RESOURCE_PERMISSIONS))
        if registration.public_key_thumbprint:
            if header[0].lower() != b"dpop":
                raise AuthenticationFailed("Use DPoP authorization for a key-bound device token.")
            verify_dpop(request, registration.public_key_thumbprint, access_token=raw)
        elif header[0].lower() != b"bearer":
            raise AuthenticationFailed("Use Bearer authorization for this device token.")
        return Response({"active": True, **_registration_data(registration)})


class DeviceIntrospectionView(DeviceAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [DeviceServiceAuthentication]

    @swagger_auto_schema(request_body=DeviceIntrospectionSerializer, operation_summary="Backend-only device token introspection",
                         responses={200: openapi.Schema(type=openapi.TYPE_OBJECT, required=["active"], properties={
                             "active": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                             "device_id": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
                             "organization_id": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
                             "tenant_id": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
                             "scopes": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_STRING)),
                         }), 400: DeviceErrorSerializer, 401: DeviceErrorSerializer, 403: DeviceErrorSerializer})
    def post(self, request):
        data = _validated(DeviceIntrospectionSerializer, request.data)
        if data["audience"] not in settings.DEVICE_ALLOWED_AUDIENCES + list(RESOURCE_PERMISSIONS):
            raise PermissionDenied("Unsupported device audience.")
        try:
            registration, claims = device_token_registration(data["access_token"], data["audience"])
        except AuthenticationFailed:
            return Response({"active": False})
        service = request.user.service
        if ((service.organization_id and service.organization_id != registration.organization_id)
                or (service.tenant_id and service.tenant_id != registration.tenant_id)):
            return Response({"active": False})
        # A key-bound resource must ALSO validate its request's DPoP proof and ath.
        return Response({"active": True, "iss": claims["iss"], "sub": claims["sub"],
                         "exp": claims["exp"], "token_type": "device", "cnf": claims.get("cnf"),
                         **_registration_data(registration), 'audience': claims['aud'],
                         'scopes': claims['scopes'], 'permissions': claims.get('permissions', []),
                         'roles': claims.get('roles', [])})
