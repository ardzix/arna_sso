"""Opaque app sessions for server-side BFFs. No refresh tokens in browsers."""
import secrets

from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session as BrowserSession
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework.response import Response
from iam.bnk_access import APP_CLIENT as BNK_IAM_APP_CLIENT
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.throttling import SimpleRateThrottle

from authentication.models import SSOAppSession, SSOAuthorizationCode, SSOAllowedRedirectURI
from authentication.serializers import MyTokenObtainPairSerializer
from authentication.sso_views import (
    SSOTokenExchangeSerializer, _browser_fingerprint, _challenge_from_verifier,
    _is_redirect_allowed,
)

APP_CLIENTS = frozenset({"arna-account", "arnasite-dashboard", "arnaos", "arna-clockin"})


class AppSessionThrottle(SimpleRateThrottle):
    scope = "app_session"
    rate = "120/min"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class AppResolveThrottle(AppSessionThrottle):
    scope = "app_session_resolve"
    rate = "2400/min"


def failure(detail="Your SSO session has ended. Please sign in again.", status=401):
    return Response({"error": "session_required" if status == 401 else "invalid_request", "detail": detail}, status=status)


def central_session(key, user):
    store = SessionStore(session_key=key)
    valid = (user.is_active and store.get("browser_user") == str(user.pk)
             and constant_time_compare(store.get("auth_fingerprint", ""), _browser_fingerprint(user)))
    return store if valid else None


@method_decorator(never_cache, name="dispatch")
class AppSessionCreateView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [AppSessionThrottle]

    def post(self, request):
        serializer = SSOTokenExchangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if data["client_id"] not in APP_CLIENTS or not SSOAllowedRedirectURI.objects.filter(
            client_id=data["client_id"], redirect_uri=data["redirect_uri"], is_active=True
        ).exists():
            return failure("Application callback is not registered.", 400)
        with transaction.atomic():
            code = SSOAuthorizationCode.objects.select_for_update().select_related("user").filter(
                code_hash=SSOAuthorizationCode.hash_code(data["code"]), client_id=data["client_id"],
                redirect_uri=data["redirect_uri"], used_at__isnull=True, expires_at__gt=timezone.now(),
                code_challenge_method="S256",
            ).first()
            if not code or not constant_time_compare(_challenge_from_verifier(data["code_verifier"], "S256"), code.code_challenge):
                return failure("Invalid, expired or already used sign-in code.", 400)
            store = central_session(code.browser_session_key, code.user) if code.browser_session_key else None
            if store is None:
                return failure()
            raw = secrets.token_urlsafe(48)
            expires_at = BrowserSession.objects.filter(session_key=code.browser_session_key,
                                                        expire_date__gt=timezone.now()).values_list("expire_date", flat=True).first()
            if expires_at is None:
                return failure()
            SSOAppSession.objects.create(
                credential_hash=SSOAuthorizationCode.hash_code(raw), user=code.user,
                client_id=code.client_id, browser_session_key=code.browser_session_key,
                expires_at=expires_at,
            )
            code.mark_used()
        return Response({"session": raw, "expires_in": max(0, int((expires_at-timezone.now()).total_seconds()))}, status=201)


@method_decorator(never_cache, name="dispatch")
class AppSessionResolveView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [AppResolveThrottle]

    def post(self, request):
        authorization = request.headers.get("Authorization", "")
        raw = authorization[7:] if authorization.startswith("Bearer ") else ""
        client_id = request.data.get("client_id") if isinstance(request.data, dict) else None
        if len(raw) != 64 or client_id not in APP_CLIENTS:
            return failure()
        app = SSOAppSession.objects.select_related("user").filter(
            credential_hash=SSOAuthorizationCode.hash_code(raw), client_id=client_id,
            revoked_at__isnull=True, expires_at__gt=timezone.now(),
        ).first()
        if not app or central_session(app.browser_session_key, app.user) is None:
            return failure()
        # Only the BFF receives this short-lived token. Membership is recomputed
        # on each resolution rather than copied from a browser-supplied profile.
        access = MyTokenObtainPairSerializer.access_for_user(app.user)
        access["iss"] = settings.DEVICE_TOKEN_ISSUER
        if app.client_id == BNK_IAM_APP_CLIENT:
            access["app_client_id"] = BNK_IAM_APP_CLIENT
        if app.client_id == "arnaos":
            access["aud"] = "arnaos"
        profile = {key: access.get(key) for key in (
            "user_id", "email", "org_id", "org_name", "roles", "permissions", "is_owner",
        )}
        profile["full_name"] = app.user.get_full_name()
        return Response({"access": str(access), "profile": profile,
                         "expires_in": max(0, int((app.expires_at-timezone.now()).total_seconds()))})


class AppSessionRevokeView(AppSessionResolveView):
    def post(self, request):
        authorization = request.headers.get("Authorization", "")
        raw = authorization[7:] if authorization.startswith("Bearer ") else ""
        client_id = request.data.get("client_id") if isinstance(request.data, dict) else None
        if len(raw) != 64 or client_id not in APP_CLIENTS:
            return failure()
        app = SSOAppSession.objects.filter(credential_hash=SSOAuthorizationCode.hash_code(raw), client_id=client_id,
                                           revoked_at__isnull=True, expires_at__gt=timezone.now()).first()
        if not app:
            return failure()
        SSOAppSession.objects.filter(pk=app.pk, revoked_at__isnull=True).update(revoked_at=timezone.now())
        if request.data.get("all") is True:
            SessionStore(session_key=app.browser_session_key).delete()
        return Response({"logged_out": True})
