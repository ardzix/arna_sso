from django.db.models.signals import post_save
from django.dispatch import receiver
from organization.models import Organization
from .models import Permission
from .effective import STORAGE_PERMISSIONS, COMMERCE_DEVICE_PERMISSIONS, COMMERCE_CATALOG_PERMISSIONS


@receiver(post_save, sender=Organization)
def provision_storage_permissions(sender, instance, created, **kwargs):
    if created:
        for name in sorted(STORAGE_PERMISSIONS | COMMERCE_DEVICE_PERMISSIONS | COMMERCE_CATALOG_PERMISSIONS):
            Permission.objects.get_or_create(organization=instance, name=name,
                                            defaults={'description': 'Resource permission for human and device principals.'})
