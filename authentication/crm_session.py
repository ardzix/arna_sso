"""Back-channel CRM grants for an already authenticated central BNK session."""
import time

from django.conf import settings
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import AccessToken

from authentication.crm_proof import crm_dashboard_proof
from organization.models import OrganizationMember


class CRMGrantUserThrottle(SimpleRateThrottle):
    scope = "crm_session_user"
    rate = "120/min"

    def get_cache_key(self, request, view):
        identity = str(request.user.pk) if request.user.is_authenticated else self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": identity}


class CRMGrantIPThrottle(SimpleRateThrottle):
    scope = "crm_session_ip"
    rate = "600/min"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class CRMTokenView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [CRMGrantUserThrottle, CRMGrantIPThrottle]

    def post(self, request):
        source = request.auth
        if (source.get("token_type") != "access" or source.get("principal_type", "user") != "user"
                or source.get("app_client_id") != "arnasite-dashboard"
                or source.get("iss") != settings.DEVICE_TOKEN_ISSUER or source.get("aud") is not None
                or source.get("device_id") or source.get("tenant_ids")):
            raise PermissionDenied("Resolve an active central BNK session before opening CRM.")
        member = OrganizationMember.objects.filter(user=request.user, is_session_active=True).first()
        if not member or source.get("org_id") != str(member.organization_id):
            raise PermissionDenied("Your active organization has changed. Refresh and retry.")
        # SSO recomputes IAM; ArnaSite verifies the current active workspaces.
        proof = crm_dashboard_proof(request.user)
        token = AccessToken(proof["access"])
        token["exp"] = min(token["exp"], source["exp"])
        return Response({"access_token": str(token), "token_type": "Bearer", "audience": "arna-crm",
                         "expires_in": max(0, token["exp"] - int(time.time()))})
