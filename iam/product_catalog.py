import hashlib
import json

from django.conf import settings
from django.db import transaction
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.service_authentication import ServicePrincipal, ServiceTokenAuthentication
from iam.models import (
    Permission,
    ProductManagedRole,
    ProductProvisioning,
    ProductProvisioningEvent,
    Role,
)
from organization.models import Organization


class ProductPermissionSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(required=False, allow_blank=True, default="")


class ProductRoleSerializer(serializers.Serializer):
    key = serializers.SlugField(max_length=80)
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(required=False, allow_blank=True, default="")
    permissions = serializers.ListField(child=serializers.CharField(max_length=255))


class ProductCatalogSerializer(serializers.Serializer):
    catalog_version = serializers.IntegerField(min_value=1)
    permissions = ProductPermissionSerializer(many=True)
    roles = ProductRoleSerializer(many=True)

    def validate(self, attrs):
        permission_names = [item["name"] for item in attrs["permissions"]]
        role_keys = [item["key"] for item in attrs["roles"]]
        if len(permission_names) != len(set(permission_names)):
            raise serializers.ValidationError({"permissions": "Permission names must be unique."})
        if len(role_keys) != len(set(role_keys)):
            raise serializers.ValidationError({"roles": "Managed role keys must be unique."})
        available = set(permission_names)
        unknown = sorted({name for role in attrs["roles"] for name in role["permissions"] if name not in available})
        if unknown:
            raise serializers.ValidationError({"roles": f"Roles reference unknown permissions: {', '.join(unknown)}"})
        return attrs


def _manifest_hash(payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ProductCatalogProvisionView(APIView):
    authentication_classes = [ServiceTokenAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_scope = "iam_catalog_provision"

    def post(self, request, product_key):
        principal = request.user
        if not isinstance(principal, ServicePrincipal):
            return Response({"error": "A service identity is required."}, status=status.HTTP_403_FORBIDDEN)
        required_scope = f"iam.catalog.provision:{product_key}"
        if required_scope not in principal.scopes:
            return Response({"error": f"{required_scope} scope is required."}, status=status.HTTP_403_FORBIDDEN)
        if principal.organization_id is None:
            return Response({"error": "The service account must be bound to an organization."}, status=status.HTTP_403_FORBIDDEN)

        serializer = ProductCatalogSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        prefixes = tuple(settings.IAM_PRODUCT_PERMISSION_PREFIXES.get(product_key, (f"{product_key}.",)))
        invalid_names = sorted(
            item["name"] for item in payload["permissions"] if not item["name"].startswith(prefixes)
        )
        if invalid_names:
            return Response(
                {"error": f"Permission namespace is not owned by {product_key}: {', '.join(invalid_names)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            organization = Organization.objects.select_for_update().get(pk=principal.organization_id)
            existing = ProductProvisioning.objects.filter(
                organization=organization, product_key=product_key
            ).first()
            if existing and existing.catalog_version > payload["catalog_version"]:
                return Response(
                    {"error": "Catalog downgrade is not allowed."}, status=status.HTTP_409_CONFLICT
                )

            created_permissions = 0
            updated_permissions = 0
            permission_records = {}
            for item in payload["permissions"]:
                permission, created = Permission.objects.get_or_create(
                    organization=organization,
                    name=item["name"],
                    defaults={"description": item["description"]},
                )
                created_permissions += int(created)
                if not created and permission.description != item["description"]:
                    permission.description = item["description"]
                    permission.save(update_fields=["description"])
                    updated_permissions += 1
                permission_records[item["name"]] = permission

            created_roles = 0
            added_role_permissions = 0
            role_results = []
            for item in payload["roles"]:
                managed = ProductManagedRole.objects.filter(
                    organization=organization, product_key=product_key, managed_key=item["key"]
                ).select_related("role").first()
                if managed is None:
                    if Role.objects.filter(organization=organization, name=item["name"]).exists():
                        raise serializers.ValidationError({
                            "roles": f"Role name '{item['name']}' already exists and is not managed by {product_key}."
                        })
                    role = Role.objects.create(
                        organization=organization, name=item["name"], description=item["description"]
                    )
                    managed = ProductManagedRole.objects.create(
                        organization=organization,
                        product_key=product_key,
                        managed_key=item["key"],
                        role=role,
                        catalog_version=payload["catalog_version"],
                    )
                    created_roles += 1
                else:
                    role = managed.role
                    managed.catalog_version = payload["catalog_version"]
                    managed.save(update_fields=["catalog_version"])

                requested_permissions = [permission_records[name] for name in item["permissions"]]
                existing_ids = set(role.permissions.values_list("id", flat=True))
                additions = [permission for permission in requested_permissions if permission.id not in existing_ids]
                role.permissions.add(*additions)
                added_role_permissions += len(additions)
                role_results.append({"key": item["key"], "name": role.name, "id": str(role.id)})

            result = {
                "permissions_created": created_permissions,
                "permissions_updated": updated_permissions,
                "roles_created": created_roles,
                "role_permissions_added": added_role_permissions,
            }
            manifest_hash = _manifest_hash(payload)
            provisioning, provisioning_created = ProductProvisioning.objects.update_or_create(
                organization=organization,
                product_key=product_key,
                defaults={
                    "catalog_version": payload["catalog_version"],
                    "manifest_hash": manifest_hash,
                    "service_client_id": principal.client_id,
                },
            )
            ProductProvisioningEvent.objects.create(
                organization=organization,
                product_key=product_key,
                catalog_version=payload["catalog_version"],
                service_client_id=principal.client_id,
                result=result,
            )

        return Response({
            "organization_id": str(organization.id),
            "organization_name": organization.name,
            "product_key": product_key,
            "catalog_version": provisioning.catalog_version,
            "manifest_hash": provisioning.manifest_hash,
            "created": provisioning_created,
            "result": result,
            "roles": role_results,
        })
