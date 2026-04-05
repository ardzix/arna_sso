"""
Passkey (WebAuthn / FIDO2) API views.

Login flow (4th option alongside Password, Google, WhatsApp):
    1. GET  /auth/passkeys/login/begin/     → returns PublicKeyCredentialRequestOptions (JSON)
    2. POST /auth/passkeys/login/complete/  → verifies assertion, issues JWT tokens (skips MFA)

Registration flow (authenticated user adds a passkey to their account):
    1. GET  /auth/passkeys/register/begin/     → returns PublicKeyCredentialCreationOptions (JSON)
    2. POST /auth/passkeys/register/complete/  → stores credential

Session note: the FIDO2 challenge is stored in request.session between begin and complete.
The browser automatically sends the session cookie, just like it does for Google OAuth flows.
"""
import logging

from django.conf import settings
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
)

# django-passkeys helpers
from passkeys.FIDO2 import enable_json_mapping, getServer, get_current_platform
from passkeys.models import UserPasskey

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from authentication.serializers import MyTokenObtainPairSerializer
from authentication.signals import user_logged_in
from user_profile.models import UserProfile

from base64 import urlsafe_b64encode


logger = logging.getLogger(__name__)
REGISTER_STATE_KEY = "fido2_register_state"
LOGIN_STATE_KEY = "fido2_login_state"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_user_credentials(user):
    """Return stored credential data for a user."""
    return [
        AttestedCredentialData(websafe_decode(uk.token))
        for uk in UserPasskey.objects.filter(user=user)
    ]


# ---------------------------------------------------------------------------
# Registration — Begin
# ---------------------------------------------------------------------------

class PasskeyRegisterBeginView(APIView):
    """
    Step 1 of passkey registration.
    Requires the user to be authenticated via JWT.
    Returns PublicKeyCredentialCreationOptions to pass to navigator.credentials.create().
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]  # No SessionAuthentication — avoids CSRF enforcement

    @swagger_auto_schema(
        operation_summary="Passkey Register — Begin",
        operation_description=(
            "Initiate passkey registration for the currently authenticated user.\n\n"
            "**Client flow:**\n"
            "1. Call this endpoint with `Authorization: Bearer <access_token>`.\n"
            "2. Pass the returned `publicKey` options to `navigator.credentials.create()`.\n"
            "3. POST the result to `/auth/passkeys/register/complete/`.\n\n"
            "A session cookie is returned alongside the response. The browser must send it "
            "back in the complete step (this happens automatically in browser environments)."
        ),
        responses={
            200: openapi.Response(
                description="PublicKeyCredentialCreationOptions",
                examples={
                    "application/json": {
                        "publicKey": {
                            "rp": {"name": "Arna SSO", "id": "localhost"},
                            "user": {
                                "name": "user@example.com",
                                "displayName": "user@example.com",
                                "id": "dXNlckBleGFtcGxlLmNvbQ=="
                            },
                            "challenge": "base64url-encoded-challenge",
                            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                            "timeout": 60000,
                            "excludeCredentials": [],
                            "authenticatorSelection": {
                                "residentKey": "preferred"
                            },
                            "attestation": "none"
                        }
                    }
                }
            ),
            401: "Unauthorized — valid JWT required",
        }
    )
    def get(self, request):
        try:
            enable_json_mapping()
            server = getServer(request)
            auth_attachment = getattr(settings, 'KEY_ATTACHMENT', None)
            username = request.user.get_username()

            registration_data, state = server.register_begin(
                {
                    'id': urlsafe_b64encode(username.encode('utf-8')),
                    'name': username,
                    'displayName': request.user.get_full_name() or username,
                },
                _get_user_credentials(request.user),
                authenticator_attachment=auth_attachment,
            )
            request.session[REGISTER_STATE_KEY] = state
            request.session.save()
            return Response(dict(registration_data), status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Passkey register begin failed")
            return Response(
                {"error": "Failed to begin registration"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# ---------------------------------------------------------------------------
# Registration — Complete
# ---------------------------------------------------------------------------

class PasskeyRegisterCompleteView(APIView):
    """
    Step 2 of passkey registration.
    Requires JWT auth + the session cookie from the begin step.
    Body: the PublicKeyCredential JSON from navigator.credentials.create().
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Passkey Register — Complete",
        operation_description=(
            "Complete passkey registration.\n\n"
            "Send the raw output of `navigator.credentials.create()` as the request body.\n"
            "Optionally include a `key_name` field to label the key (e.g. `\"My YubiKey\"`).\n\n"
            "**Note:** The session cookie from the begin step must be included (browsers do this automatically)."
        ),
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["id", "rawId", "response", "type"],
            properties={
                "id": openapi.Schema(type=openapi.TYPE_STRING, description="Base64url credential id"),
                "rawId": openapi.Schema(type=openapi.TYPE_STRING, description="Base64url raw id"),
                "response": openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "attestationObject": openapi.Schema(type=openapi.TYPE_STRING),
                        "clientDataJSON": openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
                "type": openapi.Schema(type=openapi.TYPE_STRING, example="public-key"),
                "key_name": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Optional display name for this key (e.g. 'MacBook Touch ID')",
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="Registration successful",
                examples={"application/json": {"status": "OK", "key_name": "MacBook Touch ID"}}
            ),
            400: openapi.Response(description="Registration failed — missing session state or invalid credential"),
            401: "Unauthorized — valid JWT required",
        }
    )
    def post(self, request):
        if REGISTER_STATE_KEY not in request.session:
            return Response(
                {"error": "No active registration session. Please call /register/begin/ first."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            enable_json_mapping()
            server = getServer(request)

            data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
            key_name = data.pop('key_name', '') if isinstance(data, dict) else ''

            state = request.session.pop(REGISTER_STATE_KEY)
            auth_data = server.register_complete(state, response=data)

            encoded = websafe_encode(auth_data.credential_data)
            credential_id = websafe_encode(auth_data.credential_data.credential_id)
            platform = get_current_platform(request)
            display_name = key_name or platform

            uk = UserPasskey(
                user=request.user,
                token=encoded,
                name=display_name,
                platform=platform,
                credential_id=credential_id,
            )
            uk.save()

            return Response({"status": "OK", "key_name": display_name}, status=status.HTTP_200_OK)

        except Exception:
            logger.exception("Passkey register complete failed")
            return Response(
                {"error": "Registration failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ---------------------------------------------------------------------------
# Login — Begin
# ---------------------------------------------------------------------------

class PasskeyLoginBeginView(APIView):
    """
    Step 1 of passkey login. No authentication required.
    Returns PublicKeyCredentialRequestOptions to pass to navigator.credentials.get().
    """
    permission_classes = [AllowAny]
    authentication_classes = []  # No auth needed; no CSRF enforcement

    @swagger_auto_schema(
        operation_summary="Passkey Login — Begin",
        operation_description=(
            "Initiate passkey login. No authentication required.\n\n"
            "**Client flow:**\n"
            "1. Call this endpoint (no headers needed).\n"
            "2. Pass the returned `publicKey` options to `navigator.credentials.get()`.\n"
            "3. POST the result to `/auth/passkeys/login/complete/`.\n\n"
            "A session cookie is set. The browser must include it in the complete step "
            "(happens automatically in browser environments)."
        ),
        responses={
            200: openapi.Response(
                description="PublicKeyCredentialRequestOptions",
                examples={
                    "application/json": {
                        "publicKey": {
                            "challenge": "base64url-encoded-challenge",
                            "timeout": 60000,
                            "rpId": "localhost",
                            "allowCredentials": [],
                            "userVerification": "preferred"
                        }
                    }
                }
            ),
        }
    )
    def get(self, request):
        try:
            enable_json_mapping()
            server = getServer(request)
            auth_data, state = server.authenticate_begin()
            request.session[LOGIN_STATE_KEY] = state
            request.session.save()
            return Response(dict(auth_data), status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Passkey login begin failed")
            return Response(
                {"error": "Failed to begin login"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# ---------------------------------------------------------------------------
# Login — Complete
# ---------------------------------------------------------------------------

class PasskeyLoginCompleteView(APIView):
    """
    Step 2 of passkey login.
    Verifies the WebAuthn assertion and issues JWT tokens directly (MFA skipped —
    passkeys are phishing-resistant strong 2FA by nature).
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    @swagger_auto_schema(
        operation_summary="Passkey Login — Complete",
        operation_description=(
            "Complete passkey login and receive JWT tokens.\n\n"
            "Send the raw output of `navigator.credentials.get()` as the request body.\n\n"
            "**MFA is skipped** — passkeys are a phishing-resistant authenticator "
            "equivalent to a hardware 2FA token.\n\n"
            "**Note:** The session cookie from the begin step must be included "
            "(browsers do this automatically). This endpoint does **not** require "
            "an Authorization header."
        ),
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["id", "rawId", "response", "type"],
            properties={
                "id": openapi.Schema(type=openapi.TYPE_STRING, description="Base64url credential id"),
                "rawId": openapi.Schema(type=openapi.TYPE_STRING, description="Base64url raw id"),
                "response": openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "authenticatorData": openapi.Schema(type=openapi.TYPE_STRING),
                        "clientDataJSON": openapi.Schema(type=openapi.TYPE_STRING),
                        "signature": openapi.Schema(type=openapi.TYPE_STRING),
                        "userHandle": openapi.Schema(type=openapi.TYPE_STRING),
                    }
                ),
                "type": openapi.Schema(type=openapi.TYPE_STRING, example="public-key"),
            },
        ),
        responses={
            200: openapi.Response(
                description="Login successful — JWT tokens returned",
                examples={
                    "application/json": {
                        "refresh": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "access": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "email": "user@example.com",
                        "full_name": "User Name",
                    }
                }
            ),
            400: openapi.Response(
                description="Login failed",
                examples={
                    "application/json": {
                        "error": "No active login session. Please call /login/begin/ first."
                    }
                }
            ),
        }
    )
    def post(self, request):
        if LOGIN_STATE_KEY not in request.session:
            return Response(
                {"error": "No active login session. Please call /login/begin/ first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            enable_json_mapping()
            server = getServer(request)

            data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
            credential_id = data.get('id')

            if not credential_id:
                return Response({"error": "Missing credential id"}, status=status.HTTP_400_BAD_REQUEST)

            # Look up the stored passkey by credential_id
            keys = UserPasskey.objects.filter(credential_id=credential_id, enabled=True)
            if not keys.exists():
                return Response(
                    {"error": "Passkey verification failed"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            key = keys.first()
            credentials = [AttestedCredentialData(websafe_decode(key.token))]

            state = request.session.pop(LOGIN_STATE_KEY)

            # Verify the assertion — raises on failure
            server.authenticate_complete(state, credentials=credentials, response=data)

            # ✅ Assertion verified — issue JWT (skip MFA)
            user = key.user
            if not user.is_active:
                return Response(
                    {
                        "error": (
                            "Account is not active. Please verify your email/phone first."
                        )
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            refresh = MyTokenObtainPairSerializer.get_token(user)

            # Emit audit signal
            user_logged_in.send(
                sender=self.__class__,
                user=user,
                metadata={"method": "passkey", "key_name": key.name},
            )

            # Get profile data (same as Google login response shape)
            try:
                profile = UserProfile.objects.get(user=user)
                full_name = profile.full_name
            except UserProfile.DoesNotExist:
                full_name = ""

            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "email": user.email,
                    "full_name": full_name,
                },
                status=status.HTTP_200_OK,
            )

        except Exception:
            logger.exception("Passkey login complete failed")
            return Response(
                {"error": "Passkey verification failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ---------------------------------------------------------------------------
# List & Delete Passkeys (key management)
# ---------------------------------------------------------------------------

class PasskeyListView(APIView):
    """
    List all passkeys registered to the authenticated user.
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Passkey — List registered keys",
        operation_description="Returns all passkeys registered to the current user.",
        responses={
            200: openapi.Response(
                description="List of passkeys",
                examples={
                    "application/json": [
                        {
                            "id": 1,
                            "name": "MacBook Touch ID",
                            "platform": "Apple",
                            "last_used": "2025-01-15T10:30:00Z",
                            "created_at": "2025-01-01T08:00:00Z",
                        }
                    ]
                }
            ),
            401: "Unauthorized",
        }
    )
    def get(self, request):
        keys = UserPasskey.objects.filter(user=request.user).values(
            'id', 'name', 'platform', 'last_used', 'added_on'
        )
        result = [
            {
                "id": k['id'],
                "name": k['name'],
                "platform": k['platform'],
                "last_used": k['last_used'],
                "created_at": k['added_on'],
            }
            for k in keys
        ]
        return Response(result, status=status.HTTP_200_OK)


class PasskeyDeleteView(APIView):
    """
    Delete a specific passkey by its ID.
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Passkey — Delete a key",
        operation_description=(
            "Delete a registered passkey.\n\n"
            "`id` is the passkey's database ID (from the list endpoint)."
        ),
        responses={
            200: openapi.Response(
                description="Passkey deleted",
                examples={"application/json": {"status": "OK", "message": "Passkey deleted."}}
            ),
            403: "Forbidden — key belongs to another user",
            404: "Not found",
        }
    )
    def delete(self, request, pk):
        try:
            key = UserPasskey.objects.get(pk=pk)
        except UserPasskey.DoesNotExist:
            return Response({"error": "Passkey not found."}, status=status.HTTP_404_NOT_FOUND)

        if key.user != request.user:
            return Response({"error": "Forbidden."}, status=status.HTTP_403_FORBIDDEN)

        key.delete()
        return Response({"status": "OK", "message": "Passkey deleted."}, status=status.HTTP_200_OK)
