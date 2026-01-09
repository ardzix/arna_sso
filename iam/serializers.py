from rest_framework import serializers
from .models import Role, Permission, UserRole, UserPermission

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'description']

class RoleSerializer(serializers.ModelSerializer):
    # Tampilkan detail permission, bukan cuma ID-nya
    permissions = PermissionSerializer(many=True, read_only=True)
    # Untuk write (create/update), kita butuh list of ID
    permission_ids = serializers.ListField(
        child=serializers.UUIDField(), write_only=True, required=False
    )

    organization_name = serializers.ReadOnlyField(source='organization.name')

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'organization', 'organization_name', 'permissions', 'permission_ids']
        # organization removed from read_only_fields to allow custom role creation
        read_only_fields = [] 

    def create(self, validated_data):
        # Extract permission_ids list from input (it's not a direct model field)
        perm_ids = validated_data.pop('permission_ids', [])
        
        # 1. Create the Role instance first (in iam_role table)
        role = Role.objects.create(**validated_data)
        
        # 2. If permissions are provided, set the Many-to-Many relation
        # This populates the hidden iam_role_permissions table
        if perm_ids:
            role.permissions.set(perm_ids)
        return role

    def update(self, instance, validated_data):
        perm_ids = validated_data.pop('permission_ids', None)
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        
        if perm_ids is not None:
            instance.permissions.set(perm_ids)
            
        return instance

class UserRoleSerializer(serializers.ModelSerializer):
    role_detail = RoleSerializer(source='role', read_only=True)

    user_name = serializers.ReadOnlyField(source='organization_member.user.email')
    organization_name = serializers.ReadOnlyField(source='organization_member.organization.name')

    class Meta:
        model = UserRole
        fields = ['id', 'organization_member', 'user_name', 'organization_name', 'role', 'role_detail', 'assigned_at']
        read_only_fields = ['id', 'assigned_at', 'role_detail']

    def validate(self, data):
        member = data['organization_member']
        role = data['role']
        
        # Check if role is custom (has organization)
        if role.organization:
            # SECURITY CHECK:
            # Ensure the organization_member actually belongs to the SAME organization as the role.
            if member.organization != role.organization:
                 raise serializers.ValidationError(
                    f"Membership (Org: {member.organization.name}) does not match Role Organization ({role.organization.name}). Cannot assign this role."
                )
        return data


class UserPermissionSerializer(serializers.ModelSerializer):
    # Retrieve OrganizationMember model dynamically to avoid top-level circular imports if possible, 
    # but needing it for queryset means we usually import it.
    from organization.models import OrganizationMember
    organization_member = serializers.PrimaryKeyRelatedField(queryset=OrganizationMember.objects.all())
    
    permissions = PermissionSerializer(many=True, read_only=True)
    permission_ids = serializers.ListField(
        child=serializers.UUIDField(), write_only=True, required=False
    )

    user_name = serializers.ReadOnlyField(source='organization_member.user.email')
    organization_name = serializers.ReadOnlyField(source='organization_member.organization.name')

    class Meta:
        model = UserPermission
        fields = ['id', 'organization_member', 'user_name', 'organization_name', 'permissions', 'permission_ids', 'assigned_at']
        read_only_fields = ['id', 'assigned_at']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Limit the queryset to only organization members pertinent to the request user
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
             from organization.models import OrganizationMember
             # Show members where:
             # 1. The request.user is the member (self-permission? maybe not common)
             # 2. The request.user is in the SAME organization and has an ACTIVE session
             self.fields['organization_member'].queryset = OrganizationMember.objects.filter(
                 organization__members__user=request.user,
                 organization__members__is_session_active=True
             ).distinct()

    def create(self, validated_data):
        perm_ids = validated_data.pop('permission_ids', [])
        instance = UserPermission.objects.create(**validated_data)
        if perm_ids:
            instance.permissions.set(perm_ids)
        return instance

    def update(self, instance, validated_data):
        perm_ids = validated_data.pop('permission_ids', None)
        if perm_ids is not None:
            instance.permissions.set(perm_ids)
        return super().update(instance, validated_data)

