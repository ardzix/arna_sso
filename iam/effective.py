"""One organization-scoped IAM catalogue for human and device principals."""
from .models import UserRole, UserPermission, DeviceRole, DevicePermission

STORAGE_PERMISSIONS = {
    "storage.files.read", "storage.files.create", "storage.files.update",
    "storage.files.delete", "storage.files.share", "storage.folders.create",
}
COMMERCE_DEVICE_PERMISSIONS = {
    'commerce.orders.read', 'commerce.orders.write', 'commerce.payments.create',
}
RESOURCE_PERMISSIONS = {'storage': STORAGE_PERMISSIONS, 'arna-commerce': COMMERCE_DEVICE_PERMISSIONS}


def effective_access(subject, organization, *, device=False):
    if device:
        roles = DeviceRole.objects.filter(device=subject, role__organization=organization)
        direct = DevicePermission.objects.filter(device=subject)
    else:
        roles = UserRole.objects.filter(organization_member__user=subject,
                                       organization_member__organization=organization,
                                       role__organization=organization)
        direct = UserPermission.objects.filter(organization_member__user=subject,
                                                organization_member__organization=organization)
    names = set(roles.values_list("role__name", flat=True))
    permissions = set(roles.filter(role__permissions__organization=organization)
                      .values_list("role__permissions__name", flat=True))
    permissions.update(direct.filter(permissions__organization=organization)
                       .values_list("permissions__name", flat=True))
    return sorted(names), sorted(permissions)
