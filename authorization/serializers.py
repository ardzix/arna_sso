from rest_framework import serializers
from .models import Role, Permission


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "name", "permissions", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ["id", "name", "module", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]
