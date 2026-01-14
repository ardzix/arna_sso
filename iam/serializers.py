from rest_framework import serializers
from django.db.models import Q
from .models import Role, Permission, UserRole, UserPermission

class PermissionSerializer(serializers.ModelSerializer):
    organization_name = serializers.ReadOnlyField(source='organization.name')
    organization = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Permission
        fields = ['id', 'name', 'description', 'organization', 'organization_name']
        read_only_fields = ['organization']
    
    def to_internal_value(self, data):
        # Remove organization from data if present - it will be auto-set from active session
        if isinstance(data, dict):
            data = data.copy()
            data.pop('organization', None)
        return super().to_internal_value(data)
    
    def create(self, validated_data):
        # Always set organization from active session - cannot be overridden
        # Remove organization from validated_data if somehow it got through
        validated_data.pop('organization', None)
        
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            from organization.models import OrganizationMember
            active_membership = OrganizationMember.objects.filter(
                user=request.user,
                is_session_active=True
            ).select_related('organization').first()
            
            if active_membership:
                validated_data['organization'] = active_membership.organization
            else:
                raise serializers.ValidationError({
                    'organization': 'No active organization session found. Please switch to an organization first.'
                })
        else:
            raise serializers.ValidationError({
                'organization': 'Authentication required.'
            })
        return super().create(validated_data)

class RoleSerializer(serializers.ModelSerializer):
    # Tampilkan detail permission, bukan cuma ID-nya
    permissions = PermissionSerializer(many=True, read_only=True)
    # Untuk write (create/update), kita butuh list of ID
    permission_ids = serializers.ListField(
        child=serializers.UUIDField(), write_only=True, required=False
    )

    organization_name = serializers.ReadOnlyField(source='organization.name')
    organization = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'organization', 'organization_name', 'permissions', 'permission_ids']
        read_only_fields = ['organization']
    
    def to_internal_value(self, data):
        # Remove organization from data if present - it will be auto-set from active session
        if isinstance(data, dict):
            data = data.copy()
            data.pop('organization', None)
        return super().to_internal_value(data)
    
    def create(self, validated_data):
        # Always set organization from active session - cannot be overridden
        # Remove organization from validated_data if somehow it got through
        validated_data.pop('organization', None)
        
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            from organization.models import OrganizationMember
            active_membership = OrganizationMember.objects.filter(
                user=request.user,
                is_session_active=True
            ).select_related('organization').first()
            
            if active_membership:
                validated_data['organization'] = active_membership.organization
            else:
                raise serializers.ValidationError({
                    'organization': 'No active organization session found. Please switch to an organization first.'
                })
        else:
            raise serializers.ValidationError({
                'organization': 'Authentication required.'
            })
        
        # Extract permission_ids list from input (it's not a direct model field)
        perm_ids = validated_data.pop('permission_ids', [])
        
        # Get organization that will be used (from active session)
        role_org = validated_data.get('organization')
        if not role_org:
            raise serializers.ValidationError({
                'organization': ['Organization is required.']
            })
        
        # Validate permission_ids BEFORE creating role
        if perm_ids:
            try:
                # Get all permissions that exist
                permissions = Permission.objects.filter(id__in=perm_ids).select_related('organization')
                found_permissions = {str(p.id): p for p in permissions}
                requested_ids = [str(pid) for pid in perm_ids]
                
                # Check if all requested permissions exist
                missing_ids = [pid for pid in requested_ids if pid not in found_permissions]
                if missing_ids:
                    raise serializers.ValidationError({
                        'permission_ids': [f"One or more permissions not found: {', '.join(missing_ids)}"]
                    })
                
                # Validate permissions belong to same organization
                invalid_perms = []
                for perm_id_str, perm in found_permissions.items():
                    # Permission must belong to the same organization as role
                    # No global permissions allowed - all permissions are organization-specific
                    if perm.organization != role_org:
                        invalid_perms.append(f"'{perm.name}' (org: {perm.organization.name})")
                
                if invalid_perms:
                    raise serializers.ValidationError({
                        'permission_ids': [f"Permissions must belong to the same organization as the role. Invalid: {', '.join(invalid_perms)}"]
                    })
            except serializers.ValidationError:
                # Re-raise ValidationError as-is (already formatted correctly)
                raise
            except (ValueError, TypeError) as e:
                raise serializers.ValidationError({
                    'permission_ids': [f"Invalid permission ID format: {str(e)}"]
                })
            except Exception as e:
                # For other exceptions, extract clean error message
                error_msg = str(e)
                if isinstance(e, serializers.ValidationError):
                    if hasattr(e, 'detail'):
                        if isinstance(e.detail, dict):
                            # Extract first error message from dict
                            for key, value in e.detail.items():
                                if isinstance(value, list):
                                    error_msg = value[0] if value else str(e)
                                else:
                                    error_msg = str(value)
                                break
                        else:
                            error_msg = str(e.detail)
                    else:
                        error_msg = str(e)
                raise serializers.ValidationError({
                    'permission_ids': [f"Error validating permissions: {error_msg}"]
                })
        
        # 1. Create the Role instance (all validations passed)
        try:
            role = Role.objects.create(**validated_data)
        except Exception as e:
            raise serializers.ValidationError({
                'non_field_errors': [f"Error creating role: {str(e)}"]
            })
        
        # 2. If permissions are provided, set the Many-to-Many relation
        if perm_ids:
            try:
                role.permissions.set(perm_ids)
            except Exception as e:
                # Rollback role creation if setting permissions fails
                try:
                    role.delete()
                except:
                    pass
                # Extract clean error message
                error_msg = str(e)
                if isinstance(e, serializers.ValidationError):
                    if hasattr(e, 'detail'):
                        if isinstance(e.detail, dict):
                            # Extract first error message from dict
                            for key, value in e.detail.items():
                                if isinstance(value, list):
                                    error_msg = value[0] if value else str(e)
                                else:
                                    error_msg = str(value)
                                break
                        else:
                            error_msg = str(e.detail)
                    else:
                        error_msg = str(e)
                raise serializers.ValidationError({
                    'permission_ids': [f"Error setting permissions: {error_msg}"]
                })
        return role

    def update(self, instance, validated_data):
        perm_ids = validated_data.pop('permission_ids', None)
        
        # Organization cannot be changed - always use instance's organization
        # Remove organization from validated_data if present (should not be, but safety check)
        validated_data.pop('organization', None)
        
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        
        if perm_ids is not None:
            # Validate all permission IDs exist
            if perm_ids:
                # Get all permissions that exist
                permissions = Permission.objects.filter(id__in=perm_ids)
                found_ids = set(str(p.id) for p in permissions)
                requested_ids = set(str(pid) for pid in perm_ids)
                
                # Check if all requested permissions exist
                missing_ids = requested_ids - found_ids
                if missing_ids:
                    raise serializers.ValidationError({
                        'permission_ids': [f"One or more permissions not found: {', '.join(missing_ids)}"]
                    })
                
                # Validate permissions belong to same organization
                role_org = instance.organization
                invalid_perms = []
                for perm in permissions:
                    # Permission must belong to the same organization as role
                    # No global permissions allowed - all permissions are organization-specific
                    if perm.organization != role_org:
                        invalid_perms.append(f"'{perm.name}' (org: {perm.organization.name})")
                
                if invalid_perms:
                    raise serializers.ValidationError({
                        'permission_ids': [f"Permissions must belong to the same organization as the role. Invalid: {', '.join(invalid_perms)}"]
                    })
                
                # All validations passed, set permissions
                try:
                    instance.permissions.set(perm_ids)
                except Exception as e:
                    # Extract clean error message
                    error_msg = str(e)
                    if isinstance(e, serializers.ValidationError):
                        if hasattr(e, 'detail'):
                            if isinstance(e.detail, dict):
                                # Extract first error message from dict
                                for key, value in e.detail.items():
                                    if isinstance(value, list):
                                        error_msg = value[0] if value else str(e)
                                    else:
                                        error_msg = str(value)
                                    break
                            else:
                                error_msg = str(e.detail)
                        else:
                            error_msg = str(e)
                    raise serializers.ValidationError({
                        'permission_ids': [f"Error setting permissions: {error_msg}"]
                    })
            else:
                # Empty list - clear all permissions
                try:
                    instance.permissions.clear()
                except Exception as e:
                    raise serializers.ValidationError({
                        'permission_ids': [f"Error clearing permissions: {str(e)}"]
                    })
            
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
        
        # SECURITY CHECK:
        # All roles are organization-specific - ensure the organization_member 
        # belongs to the SAME organization as the role.
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
            # Validate all permission IDs exist
            permissions = Permission.objects.filter(id__in=perm_ids)
            found_ids = set(str(p.id) for p in permissions)
            requested_ids = set(str(pid) for pid in perm_ids)
            
                # Check if all requested permissions exist
                missing_ids = requested_ids - found_ids
                if missing_ids:
                    raise serializers.ValidationError({
                        'permission_ids': [f"One or more permissions not found: {', '.join(missing_ids)}"]
                    })
                
                # Validate permissions belong to same organization
                member_org = instance.organization_member.organization
                invalid_perms = []
                for perm in permissions:
                    # Permission must belong to the same organization as member
                    # No global permissions allowed - all permissions are organization-specific
                    if perm.organization != member_org:
                        invalid_perms.append(f"'{perm.name}' (org: {perm.organization.name})")
                
                if invalid_perms:
                    raise serializers.ValidationError({
                        'permission_ids': [f"Permissions must belong to the same organization as the member. Invalid: {', '.join(invalid_perms)}"]
                    })
                
                # All validations passed, set permissions
                try:
                    instance.permissions.set(perm_ids)
                except Exception as e:
                    # Extract clean error message
                    error_msg = str(e)
                    if isinstance(e, serializers.ValidationError):
                        if hasattr(e, 'detail'):
                            if isinstance(e.detail, dict):
                                # Extract first error message from dict
                                for key, value in e.detail.items():
                                    if isinstance(value, list):
                                        error_msg = value[0] if value else str(e)
                                    else:
                                        error_msg = str(value)
                                    break
                            else:
                                error_msg = str(e.detail)
                        else:
                            error_msg = str(e)
                    raise serializers.ValidationError({
                        'permission_ids': [f"Error setting permissions: {error_msg}"]
                    })
        return instance

    def update(self, instance, validated_data):
        perm_ids = validated_data.pop('permission_ids', None)
        if perm_ids is not None:
            # Validate all permission IDs exist
            if perm_ids:
                # Get all permissions that exist
                permissions = Permission.objects.filter(id__in=perm_ids)
                found_ids = set(str(p.id) for p in permissions)
                requested_ids = set(str(pid) for pid in perm_ids)
                
                # Check if all requested permissions exist
                missing_ids = requested_ids - found_ids
                if missing_ids:
                    raise serializers.ValidationError({
                        'permission_ids': [f"One or more permissions not found: {', '.join(missing_ids)}"]
                    })
                
                # Validate permissions belong to same organization
                member_org = instance.organization_member.organization
                invalid_perms = []
                for perm in permissions:
                    # Permission must belong to the same organization as member
                    # No global permissions allowed - all permissions are organization-specific
                    if perm.organization != member_org:
                        invalid_perms.append(f"'{perm.name}' (org: {perm.organization.name})")
                
                if invalid_perms:
                    raise serializers.ValidationError({
                        'permission_ids': [f"Permissions must belong to the same organization as the member. Invalid: {', '.join(invalid_perms)}"]
                    })
                
                # All validations passed, set permissions
                try:
                    instance.permissions.set(perm_ids)
                except Exception as e:
                    # Extract clean error message
                    error_msg = str(e)
                    if isinstance(e, serializers.ValidationError):
                        if hasattr(e, 'detail'):
                            if isinstance(e.detail, dict):
                                # Extract first error message from dict
                                for key, value in e.detail.items():
                                    if isinstance(value, list):
                                        error_msg = value[0] if value else str(e)
                                    else:
                                        error_msg = str(value)
                                    break
                            else:
                                error_msg = str(e.detail)
                        else:
                            error_msg = str(e)
                    raise serializers.ValidationError({
                        'permission_ids': [f"Error setting permissions: {error_msg}"]
                    })
            else:
                # Empty list - clear all permissions
                try:
                    instance.permissions.clear()
                except Exception as e:
                    raise serializers.ValidationError({
                        'permission_ids': [f"Error clearing permissions: {str(e)}"]
                    })
        return super().update(instance, validated_data)

