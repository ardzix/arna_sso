from rest_framework import permissions
from iam.models import UserRole, UserPermission

class HasOrganizationPermission(permissions.BasePermission):
    """
    Base permission class to check if a user has a specific permission
    within the context of an organization.
    """
    required_permission = None

    def get_organization(self, request, view, obj=None):
        """
        Helper to extract organization from request or object.
        Must be implemented or inferred by subclasses.
        """
        # 1. Try to get from object if available
        if obj:
            if hasattr(obj, 'organization'):
                org = obj.organization
                # Validate user has access
                if self._user_has_org_access(request.user, org):
                    return org
                return None
            if hasattr(obj, 'organization_member'):
                org = obj.organization_member.organization
                if self._user_has_org_access(request.user, org):
                    return org
                return None
        
        # 2. Try to get from request data (for create actions)
        # Handle both dict and QueryDict formats
        org_id = None
        if hasattr(request.data, 'get'):
            # QueryDict or dict with .get() method
            org_id = request.data.get('organization')
        elif isinstance(request.data, dict) and 'organization' in request.data:
            org_id = request.data['organization']
        
        if org_id:
            from organization.models import Organization
            try:
                org = Organization.objects.get(pk=org_id)
                # SECURITY: Validate user has access to this organization
                if not self._user_has_org_access(request.user, org):
                    return None
                return org
            except (Organization.DoesNotExist, ValueError, TypeError):
                return None
        
        # 3. For UserRole/UserPermission creation, we get org via 'organization_member'
        if 'organization_member' in request.data:
            from organization.models import OrganizationMember
            try:
                member = OrganizationMember.objects.get(pk=request.data['organization_member'])
                # SECURITY: Validate user has access to this member's organization
                org = member.organization
                if not self._user_has_org_access(request.user, org):
                    return None
                return org
            except OrganizationMember.DoesNotExist:
                return None
        
        # 4. Fallback: For owner, try to get from active organization session
        # This allows owner to manage IAM even if organization not explicitly provided
        from organization.models import OrganizationMember
        active_membership = OrganizationMember.objects.filter(
            user=request.user,
            is_session_active=True
        ).select_related('organization').first()
        
        if active_membership:
            org = active_membership.organization
            # Owner can always manage their organization
            if org.owner == request.user:
                return org
            # For members, only return if they have access
            if self._user_has_org_access(request.user, org):
                return org
                
        return None
    
    def _user_has_org_access(self, user, org):
        """Check if user has access to organization (owner or member)"""
        if org.owner == user:
            return True
        from organization.models import OrganizationMember
        return OrganizationMember.objects.filter(user=user, organization=org).exists()

    def has_permission(self, request, view):
        # We only check permissions on modification requests generally,
        # but for this system, we might want to check even for list/retrieve depending on strictness.
        # For now, let's assume standard DRF flow:
        # has_permission is called first. 
        
        if request.method in permissions.SAFE_METHODS:
            return True
            
        # For create actions, we need to check here because there is no 'obj' yet.
        if request.method == 'POST':
            # First, try to get organization from request data or active session
            org = self.get_organization(request, view)
            
            # If organization found, check if user is owner (bypass all checks)
            if org:
                if org.owner == request.user:
                    return True
                return self._check_org_permission(request.user, org)
            
            # If organization not found, check if user is owner of active organization
            # This handles cases where organization might not be in request.data yet
            # (e.g., serializer will set it, but permission check happens first)
            from organization.models import OrganizationMember
            active_membership = OrganizationMember.objects.filter(
                user=request.user,
                is_session_active=True
            ).select_related('organization', 'organization__owner').first()
            
            if active_membership and active_membership.organization.owner == request.user:
                # Owner of active organization - allow all operations
                return True
            
            # If we can't determine organization and user is not owner of active org, deny
            return False
            
        return True

    def has_object_permission(self, request, view, obj):
        # For detail views (GET, PUT, DELETE)
        if request.method in permissions.SAFE_METHODS:
            return True
            
        org = self.get_organization(request, view, obj)
        if not org:
            return False
            
        return self._check_org_permission(request.user, org)

    def _check_org_permission(self, user, org):
        # 1. Check Owner - Owner has full access to all operations
        if org.owner == user:
            return True
            
        # 2. Check Membership
        from organization.models import OrganizationMember
        membership = OrganizationMember.objects.filter(user=user, organization=org).first()
        if not membership:
            return False
            
        # 3. Check Direct Permission
        if UserPermission.objects.filter(
            organization_member=membership, 
            permissions__name=self.required_permission
        ).exists():
            return True
            
        # 4. Check Role Permission
        if UserRole.objects.filter(
            organization_member=membership,
            role__organization=org,
            role__permissions__name=self.required_permission
        ).exists():
            return True
            
        return False


class CanManageOrganizationMembers(HasOrganizationPermission):
    required_permission = 'organization.manage_members'


class CanManageRoles(HasOrganizationPermission):
    required_permission = 'organization.manage_roles'


class CanAssignRoles(HasOrganizationPermission):
    required_permission = 'organization.manage_roles' # Usually same as managing roles


class CanAssignDirectPermissions(HasOrganizationPermission):
    required_permission = 'organization.manage_permissions'
