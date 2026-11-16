"""Tenant-scoped human CRM policy. Never authorize from browser hints."""
from uuid import UUID

CRM_PERMISSIONS = frozenset({
    "crm.read", "crm.write", "crm.manage", "crm.inbox.read", "crm.inbox.write",
})


def resolve_crm_grant(verified_tenant_ids, grants, active_tenant_id=None):
    """Select exactly one verified tenant, with no organization-wide fallback."""
    verified = {str(UUID(str(value))) for value in verified_tenant_ids}
    allowed = {}
    for grant in grants:
        tenant = str(UUID(str(grant["tenant_id"])))
        permissions = grant["permissions"]
        if (not isinstance(permissions, list) or not permissions
                or any(not isinstance(p, str) or p not in CRM_PERMISSIONS for p in permissions)):
            raise ValueError("Invalid tenant CRM permissions.")
        if tenant in verified:
            allowed.setdefault(tenant, set()).update(permissions)
    selected = str(UUID(str(active_tenant_id))) if active_tenant_id else None
    if selected is None and len(allowed) == 1:
        selected = next(iter(allowed))
    if selected not in allowed:
        raise ValueError("Select a tenant with an explicit CRM grant.")
    return selected, sorted(allowed[selected])
