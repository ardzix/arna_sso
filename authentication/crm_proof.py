"""CRM dashboard grants: identity/IAM from SSO, tenant ownership from ArnaSite."""

from uuid import UUID
from datetime import timedelta
from iam.models import CRMTenantGrant
from iam.crm_scope import resolve_crm_grant
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


def crm_dashboard_proof(user, *, requested_tenant_id=None, expected_context=None,
                        context_only=False, credential_expires_at=None):
    member = OrganizationMember.objects.select_related("organization").filter(
        user=user, is_session_active=True,
    ).first()
    if not user.is_active or not member:
        raise PermissionDenied("Select an organization before opening CRM.")
    org_id = str(member.organization_id)
    access = MyTokenObtainPairSerializer.access_for_user(user)
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
    member.refresh_from_db()
    if not member.is_session_active or str(member.organization_id) != org_id:
        raise PermissionDenied("The active organization changed. Please retry.")
    is_owner = member.organization.owner_id == user.pk
    selector = requested_tenant_id or member.active_tenant_id
    if not is_owner:
        grants = list(CRMTenantGrant.objects.filter(
            organization_member=member, is_active=True,
        ).values("id", "tenant_id", "permissions", "updated_at"))
        try:
            selected, permissions = resolve_crm_grant(
                tenant_ids, grants, selector,
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise PermissionDenied("No explicit CRM grant for the selected tenant.") from exc
        tenant_ids = {selected}
        # Never union scoped CRM permissions with organization IAM permissions.
        access["permissions"] = permissions
        access["roles"] = []
        access.payload.pop("scope", None)
        access["crm_grant_version"] = 1
    else:
        selected = str(UUID(str(selector))) if selector else None
        if selected is None and len(tenant_ids) == 1:
            selected = next(iter(tenant_ids))
        if selected not in tenant_ids:
            raise PermissionDenied("Select a verified CRM tenant.")
        tenant_ids = {selected}
    grant_revision = None if is_owner else [
        [str(g["id"]), g["updated_at"].isoformat()]
        for g in grants if str(g["tenant_id"]) == selected
    ]
    context = {
        "member_id": str(member.pk), "organization_id": org_id,
        "tenant_id": selected, "is_owner": is_owner,
        "grant_revision": grant_revision,
        "active_tenant_id": str(member.active_tenant_id) if member.active_tenant_id else None,
    }
    if expected_context is not None and context != expected_context:
        raise PermissionDenied("CRM authorization context changed. Start sign-in again.")
    if context_only:
        return context
    # Bounded revocation only: consumers validate expiry, not live grants.
    lifetime = min(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"], timedelta(seconds=60))
    if credential_expires_at is not None:
        from django.utils import timezone
        remaining = int(credential_expires_at) - int(timezone.now().timestamp())
        if remaining <= 0:
            raise PermissionDenied("The original login credential expired.")
        lifetime = min(lifetime, timedelta(seconds=remaining))
    access.set_exp(lifetime=lifetime)
    access["aud"] = "arna-crm"
    # CRM uses sub. Do not let generic SSO JWTAuthentication resolve this proof
    # into a user and mint a broader token at organization/session endpoints.
    from rest_framework_simplejwt.settings import api_settings
    if api_settings.USER_ID_CLAIM == "sub":
        raise WorkspaceUnavailable("CRM requires a distinct base SSO user ID claim.")
    access.payload.pop(api_settings.USER_ID_CLAIM, None)
    access["sub"] = str(user.pk)
    access["principal_type"] = "user"
    access["tenant_id"] = selected
    access["organization_id"] = org_id
    access["tenant_ids"] = sorted(tenant_ids)
    access["is_owner"] = is_owner
    # Local/legacy serializer hints do not override ArnaSite's membership result.
    return {"access": str(access), "token_type": "Bearer",
            "expires_in": int(lifetime.total_seconds())}
