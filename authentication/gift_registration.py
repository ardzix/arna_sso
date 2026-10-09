"""Narrow service-only identity registration; never a login or OTP endpoint."""
import hashlib
import json
import unicodedata
import uuid
from dataclasses import dataclass

import jwt
from django.conf import settings
from django.db import IntegrityError, transaction
from drf_yasg.utils import swagger_auto_schema
from rest_framework import serializers
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta

from authentication.models import ServiceAccount, TrustedRegistration, User
from user_profile.models import UserProfile

SCOPE = "sso.whatsapp.register"
AUDIENCE = "arna-sso-registration"


@dataclass
class RegistrationPrincipal:
    service: ServiceAccount
    is_authenticated: bool = True

    @property
    def pk(self):
        return self.service.pk


class RegistrationAuthentication(BaseAuthentication):
    def authenticate_header(self, request):
        return "Bearer"

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header:
            return None
        if len(header) != 2 or header[0].lower() != b"bearer":
            raise AuthenticationFailed("Invalid service authorization.")
        try:
            if settings.SIMPLE_JWT["ALGORITHM"] != "RS256":
                raise ValueError("RS256 required")
            claims = jwt.decode(
                header[1], settings.SIMPLE_JWT["VERIFYING_KEY"], algorithms=["RS256"],
                issuer=settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id",
                audience=AUDIENCE, leeway=0,
                options={"require": ["exp", "iat", "iss", "aud", "jti", "token_type", "service_id", "client_id"]},
            )
            if (claims["token_type"] != "service" or claims.get("principal_type") != "service"
                    or claims.get("scopes") != [SCOPE] or claims.get("scope") != SCOPE
                    or claims["aud"] != AUDIENCE or not 0 < claims["exp"] - claims["iat"] <= 300):
                raise ValueError("Wrong principal")
            service = ServiceAccount.objects.get(pk=uuid.UUID(claims["service_id"]), is_active=True)
            if (service.client_id != claims["client_id"] or service.scopes != [SCOPE]
                    or service.audiences != [AUDIENCE]):
                raise ValueError("Registration revoked")
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, ServiceAccount.DoesNotExist) as exc:
            raise AuthenticationFailed("Invalid or revoked registration service token.") from exc
        return RegistrationPrincipal(service), claims


class RegistrationThrottle(SimpleRateThrottle):
    scope = "trusted_registration"
    rate = "120/min"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": str(request.user.pk)}


class RegistrationSerializer(serializers.Serializer):
    phone = serializers.RegexField(r"^[1-9][0-9]{7,14}$", max_length=15)
    name = serializers.CharField(max_length=80)
    campaign = serializers.RegexField(r"^[a-zA-Z0-9_-]{1,80}$", max_length=80)
    message_id = serializers.CharField(max_length=250)

    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise ValidationError({"non_field_errors": ["Only phone, name, campaign and message_id are permitted."]})
        return super().to_internal_value(data)

    def validate_name(self, value):
        if any(unicodedata.category(c).startswith("C") for c in value):
            raise ValidationError("Invalid name.")
        value = " ".join(unicodedata.normalize("NFC", value).split())
        if (not any(unicodedata.category(c).startswith("L") for c in value)
                or any(not (unicodedata.category(c)[0] in "LMN" or c in " .'’-") for c in value)):
            raise ValidationError("Invalid name.")
        return value

    def validate_message_id(self, value):
        if any(unicodedata.category(c).startswith("C") for c in value):
            raise ValidationError("Invalid message identifier.")
        return value


class RegistrationConflict(Exception):
    pass


def register_identity(service, data):
    proof_hash = hashlib.sha256((data["campaign"] + "\n" + data["message_id"]).encode()).hexdigest()
    payload_hash = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def replay(receipt):
        if receipt.payload_hash != payload_hash:
            raise RegistrationConflict()
        return receipt.user_id, receipt.user_created, True

    receipt = TrustedRegistration.objects.filter(service=service, proof_hash=proof_hash).first()
    if receipt:
        return replay(receipt)
    try:
        with transaction.atomic():
            # The unique phone constraint makes different concurrent events safe.
            # A placeholder-email collision must not link somebody else's account.
            user, created = User.objects.get_or_create(
                phone_number=data["phone"], defaults={
                    "email": f"wa_{data['phone']}@arnatech.local",
                    "is_active": False, "phone_verified": False,
                },
            )
            if created:
                user.set_unusable_password()
                user.save(update_fields=["password"])
                UserProfile.objects.create(user=user, full_name=data["name"], phone_number=data["phone"])
            TrustedRegistration.objects.create(
                service=service, proof_hash=proof_hash, payload_hash=payload_hash,
                user=user, user_created=created,
            )
            return user.pk, created, False
    except IntegrityError as exc:
        receipt = TrustedRegistration.objects.filter(service=service, proof_hash=proof_hash).first()
        if receipt:
            return replay(receipt)
        raise RegistrationConflict() from exc


class TrustedWhatsAppRegistrationView(APIView):
    authentication_classes = [RegistrationAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [RegistrationThrottle]

    def initial(self, request, *args, **kwargs):
        self.request_id = str(uuid.uuid4())
        return super().initial(request, *args, **kwargs)

    def handle_exception(self, exc):
        response = super().handle_exception(exc)
        code = {400: "invalid_registration", 401: "invalid_service_token", 403: "registration_forbidden", 429: "rate_limited"}.get(response.status_code, "registration_failed")
        response.data = {"error": code, "detail": "Registration request could not be accepted.", "request_id": self.request_id}
        return response

    @swagger_auto_schema(request_body=RegistrationSerializer, operation_description=
        "Service-only registration from an authenticated WhatsApp gift webhook. Requires an RS256 service token "
        "with audience arna-sso-registration and only scope sso.whatsapp.register. Idempotency is scoped to "
        "service, campaign and message_id. New identities remain inactive/unverified with an unusable password. "
        "No OTP, user tokens, membership or privileges are issued; existing identities are never changed.")
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user_id, created, replayed = register_identity(request.user.service, serializer.validated_data)
        except RegistrationConflict:
            return Response({"error": "registration_conflict", "detail": "Registration identifier conflicts with existing data.", "request_id": self.request_id}, status=409)
        return Response({"user_id": str(user_id), "created": created, "replayed": replayed,
                         "status": "registered" if created else "existing", "request_id": self.request_id},
                        status=201 if created and not replayed else 200)


class RegistrationTokenThrottle(SimpleRateThrottle):
    scope = "registration_token"
    rate = "120/min"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class RegistrationTokenSerializer(serializers.Serializer):
    client_id = serializers.CharField(max_length=120)
    client_secret = serializers.CharField(max_length=256, write_only=True, trim_whitespace=False)
    audience = serializers.ChoiceField(choices=[AUDIENCE])


class RegistrationServiceTokenView(TrustedWhatsAppRegistrationView):
    """Credential exchange, with a separate quota from public OTP/login flows."""
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [RegistrationTokenThrottle]

    @swagger_auto_schema(request_body=RegistrationTokenSerializer, operation_description=
        "Registration-only client credential exchange. Returns a five-minute service token, never a user token.")
    def post(self, request):
        serializer = RegistrationTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        service = ServiceAccount.objects.filter(client_id=data["client_id"], is_active=True).first()
        if (not service or not service.check_client_secret(data["client_secret"])
                or service.scopes != [SCOPE] or service.audiences != [AUDIENCE]):
            return Response({"error": "invalid_service_credentials", "detail": "Invalid registration service credentials.", "request_id": self.request_id}, status=401)
        token = AccessToken()
        token.set_exp(lifetime=timedelta(minutes=5))
        token["iss"] = settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id"
        token["aud"] = AUDIENCE
        token["token_type"] = "service"
        token["principal_type"] = "service"
        token["service_id"] = str(service.pk)
        token["client_id"] = service.client_id
        token["scopes"] = [SCOPE]
        token["scope"] = SCOPE
        return Response({"access": str(token), "token_type": "Bearer", "expires_in": 300, "request_id": self.request_id})
