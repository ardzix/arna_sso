from rest_framework.exceptions import PermissionDenied

from organization.models import Organization, OrganizationMember

from .models import ProductManagedRole, UserRole


AUDIENCE = 'arna-bnk-iam'
APP_CLIENT = 'arnasite-dashboard'
PRODUCT_KEY = 'bnk-iam'
FULL_ADMIN = 'Full Admin'


def full_admin_name(value):
    return isinstance(value, str) and ' '.join(value.split()).casefold() == FULL_ADMIN.casefold()


def admin_assignments(organization_id):
    return UserRole.objects.filter(
        organization_member__organization_id=organization_id,
        role__organization_id=organization_id,
        role__name=FULL_ADMIN,
    )


def active_bnk_admin(user, expected_organization_id=None, *, lock=False):
    memberships = OrganizationMember.objects.select_related('organization').filter(
        user=user, user__is_active=True, is_session_active=True,
    )
    if lock:
        memberships = memberships.select_for_update(of=('self',))
    membership = memberships.first()
    if membership is None:
        raise PermissionDenied('Select an active organization to manage BNK access.')
    if expected_organization_id is not None and membership.organization_id != expected_organization_id:
        raise PermissionDenied('Your active organization has changed. Refresh and try again.')
    if membership.organization.owner_id != user.pk and not admin_assignments(membership.organization_id).filter(
        organization_member=membership,
    ).exists():
        raise PermissionDenied('BNK access management requires the organization owner or Full Admin.')
    return membership


def lock_organization(organization_id):
    return Organization.objects.select_for_update().filter(pk=organization_id).first()


def guard_legacy_role_write(user, organization, role=None, new_name=None):
    if role and ProductManagedRole.objects.filter(role=role, product_key=PRODUCT_KEY).exists():
        raise PermissionDenied('Manage this role through BNK Roles & Permissions.')
    if full_admin_name(new_name) or (role and full_admin_name(role.name)):
        if not organization or organization.owner_id != user.pk:
            raise PermissionDenied('Only the organization owner can manage Full Admin.')
