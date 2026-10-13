"""Active server-side organization and verified workspace context."""
from rest_framework.exceptions import PermissionDenied, ValidationError
from organization.models import OrganizationMember
from iam.effective import effective_access
from .device_security import tenant_workspaces, verify_tenant


def active_organization(user, organization_id=None, *, manage=True):
    membership = OrganizationMember.objects.select_related('organization').filter(
        user=user, is_session_active=True).first()
    if not user.is_active or not membership:
        raise PermissionDenied('Switch to an organization before managing devices.')
    organization = membership.organization
    if organization_id and organization.pk != organization_id:
        raise PermissionDenied('The supplied organization does not match your active organization.')
    _, permissions = effective_access(user, organization)
    if manage and organization.owner_id != user.pk and 'device.activate' not in permissions:
        raise PermissionDenied('Organization owner or device.activate permission is required.')
    return membership


def active_context(user, organization_id=None, *, manage=True):
    membership = active_organization(user, organization_id, manage=manage)
    if membership.active_tenant_id is None:
        rows = tenant_workspaces(user, membership.organization)
        if len(rows) != 1:
            raise ValidationError({'tenant_id': 'Select an active workspace through /api/v1/devices/context/ first.'})
        membership.active_tenant_id = rows[0]['tenant_id']
        membership.save(update_fields=['active_tenant_id'])
    verify_tenant(user, membership.organization, membership.active_tenant_id)
    # Re-check authority/session after a downstream lookup.
    current = active_organization(user, membership.organization_id, manage=manage)
    if current.active_tenant_id != membership.active_tenant_id:
        raise PermissionDenied('Workspace context changed. Retry in the active workspace.')
    return current
