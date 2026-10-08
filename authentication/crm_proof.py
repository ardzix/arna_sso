"""CRM dashboard grants: identity/IAM from SSO, tenant ownership from ArnaSite."""

from uuid import UUID
from urllib.parse import urlsplit

import requests
from django.conf import settings
from rest_framework.exceptions import APIException, PermissionDenied

from authentication.serializers import MyTokenObtainPairSerializer
from organization.models import OrganizationMember

CRM_CLIENT_ID = "arna-site-crm"


class WorkspaceUnavailable(APIException):
    status_code = 503
    default_detail = "ArnaSite workspace verification is temporarily unavailable."
    default_code = "workspace_unavailable"


def crm_dashboard_proof(user):
    member = OrganizationMember.objects.select_related("organization").filter(
        user=user, is_session_active=True,
    ).first()
    if not user.is_active or not member:
        raise PermissionDenied("Select an organization before opening CRM.")
    org_id = str(member.organization_id)
    access = MyTokenObtainPairSerializer.get_token(user).access_token
    if access.get("org_id") != org_id:
        raise PermissionDenied("The active organization changed. Please retry.")
    issuer = settings.SIMPLE_JWT.get("ISSUER") or "https://sso.arnatech.id"
    # A short user delegation to the product owner; no browser-provided scope.
    access["iss"] = issuer
    access["aud"] = "arna-site"
    url = getattr(settings, "CRM_ARNASITE_TENANTS_URL", "https://site.arnatech.id/tenants/")
    parsed = urlsplit(url)
    local = settings.DEBUG and parsed.hostname in {"localhost", "127.0.0.1"}
    if parsed.username or parsed.password or not parsed.hostname or (
        parsed.scheme != "https" and not (local and parsed.scheme == "http")
    ):
        raise WorkspaceUnavailable()
    try:
        response = requests.get(url, headers={"Authorization": f"Bearer {access}", "Accept": "application/json"},
                                timeout=8, allow_redirects=False)
        if response.status_code != 200:
            raise WorkspaceUnavailable()
        data = response.json()
        rows = data if isinstance(data, list) else data.get("results")
        if not isinstance(rows, list) or (isinstance(data, dict) and data.get("next")):
            raise WorkspaceUnavailable()
        tenant_ids = set()
        for row in rows:
            if not isinstance(row, dict) or str(row.get("sso_organization_id")) != org_id:
                raise WorkspaceUnavailable()
            if row.get("is_active") is True:
                tenant_ids.add(str(UUID(str(row.get("tenant_id")))))
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        raise WorkspaceUnavailable() from exc
    if not tenant_ids:
        raise PermissionDenied("This organization has no active ArnaSite workspace.")
    # Ensure membership has not been switched while resolving the workspace.
    if not OrganizationMember.objects.filter(pk=member.pk, user=user, is_session_active=True).exists():
        raise PermissionDenied("The active organization changed. Please retry.")
    access["aud"] = "arna-crm"
    access["sub"] = str(user.pk)
    access["organization_id"] = org_id
    access["tenant_ids"] = sorted(tenant_ids)
    access["is_owner"] = member.organization.owner_id == user.pk
    # Local/legacy serializer hints do not override ArnaSite's membership result.
    access.payload.pop("tenant_id", None)
    return {"access": str(access), "token_type": "Bearer",
            "expires_in": int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds())}
