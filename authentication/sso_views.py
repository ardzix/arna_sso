import base64
import hashlib
from urllib.parse import urlencode

from django.conf import settings
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from authentication.models import SSOAllowedRedirectURI, SSOAuthorizationCode
from authentication.serializers import MyTokenObtainPairSerializer

PKCE_ALLOWED_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


class SSOAuthorizeSerializer(serializers.Serializer):
    client_id = serializers.CharField(max_length=120)
    redirect_uri = serializers.URLField(max_length=500)
    code_challenge = serializers.CharField(min_length=43, max_length=128)
    code_challenge_method = serializers.ChoiceField(
        choices=("S256", "plain"),
        default="S256",
    )
    state = serializers.CharField(required=False, allow_blank=True, max_length=500)

    def validate_code_challenge(self, value):
        if not set(value).issubset(PKCE_ALLOWED_CHARS):
            raise serializers.ValidationError("Invalid PKCE code_challenge")
        return value


class SSOTokenExchangeSerializer(serializers.Serializer):
    grant_type = serializers.ChoiceField(choices=("authorization_code",))
    client_id = serializers.CharField(max_length=120)
    redirect_uri = serializers.URLField(max_length=500)
    code = serializers.CharField()
    code_verifier = serializers.CharField(min_length=43, max_length=128)

    def validate_code_verifier(self, value):
        if not set(value).issubset(PKCE_ALLOWED_CHARS):
            raise serializers.ValidationError("Invalid PKCE code_verifier")
        return value


def _is_redirect_allowed(client_id, redirect_uri):
    return SSOAllowedRedirectURI.objects.filter(
        client_id=client_id,
        redirect_uri=redirect_uri,
        is_active=True,
    ).exists() or redirect_uri in set(getattr(settings, "SSO_ALLOWED_REDIRECT_URIS", []))


def _challenge_from_verifier(verifier, method):
    if method == "plain":
        return verifier
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class SSOAuthorizeCodeView(APIView):
    """
    Create a short-lived one-time code after the user has authenticated on SSO.

    External products should redirect users to the SSO UI. After passkey/password/MFA
    login succeeds on sso.arnatech.id, that UI calls this endpoint with its JWT and
    redirects the browser to the returned redirect_url.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        serializer = SSOAuthorizeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if not request.user.is_active:
            return Response(
                {"error": "Account is not active. Please verify your email/phone first."},
                status=status.HTTP_403_FORBIDDEN,
            )

        redirect_uri = data["redirect_uri"]
        if not _is_redirect_allowed(data["client_id"], redirect_uri):
            return Response(
                {"error": "redirect_uri is not allowed"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        expires_at = timezone.now() + timezone.timedelta(
            seconds=settings.SSO_AUTH_CODE_LIFETIME_SECONDS
        )
        code, _ = SSOAuthorizationCode.create_for_user(
            user=request.user,
            client_id=data["client_id"],
            redirect_uri=redirect_uri,
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
            expires_at=expires_at,
        )

        query = {"code": code}
        if data.get("state"):
            query["state"] = data["state"]

        separator = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{separator}{urlencode(query)}"
        return Response(
            {
                "code": code,
                "redirect_url": redirect_url,
                "expires_in": settings.SSO_AUTH_CODE_LIFETIME_SECONDS,
            },
            status=status.HTTP_201_CREATED,
        )


class SSOTokenExchangeView(APIView):
    """
    Exchange a one-time SSO code for the normal Arna SSO JWT token pair.

    This endpoint is intended for the product backend callback handler, not for
    direct passkey login on unrelated product domains.
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = SSOTokenExchangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if not _is_redirect_allowed(data["client_id"], data["redirect_uri"]):
            return Response(
                {"error": "redirect_uri is not allowed"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        code_hash = SSOAuthorizationCode.hash_code(data["code"])
        auth_code = (
            SSOAuthorizationCode.objects.select_related("user")
            .filter(
                code_hash=code_hash,
                client_id=data["client_id"],
                redirect_uri=data["redirect_uri"],
            )
            .first()
        )

        if not auth_code or auth_code.is_used() or auth_code.is_expired():
            return Response(
                {"error": "Invalid or expired authorization code"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        expected_challenge = _challenge_from_verifier(
            data["code_verifier"],
            auth_code.code_challenge_method,
        )
        if not constant_time_compare(expected_challenge, auth_code.code_challenge):
            return Response(
                {"error": "Invalid code_verifier"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = auth_code.user
        if not user.is_active:
            return Response(
                {"error": "Account is not active. Please verify your email/phone first."},
                status=status.HTTP_403_FORBIDDEN,
            )

        auth_code.mark_used()
        refresh = MyTokenObtainPairSerializer.get_token(user)
        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "token_type": "Bearer",
                "expires_in": int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds()),
            },
            status=status.HTTP_200_OK,
        )
