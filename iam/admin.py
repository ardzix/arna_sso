from django.contrib import admin
from .models import Permission, Role, UserRole

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name',)

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'get_permissions', 'is_global')
    search_fields = ('name', 'organization__name')
    list_filter = ('organization',)
    filter_horizontal = ('permissions',)

    def get_permissions(self, obj):
        return ", ".join([p.name for p in obj.permissions.all()])
    get_permissions.short_description = 'Permissions'
    
    def is_global(self, obj):
        return obj.organization is None
    is_global.boolean = True
    is_global.short_description = 'Global Role'

@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ('organization_member', 'role', 'assigned_at')
    search_fields = ('organization_member__user__email', 'role__name', 'organization_member__organization__name')
    list_filter = ('role__organization', 'role')

from .models import UserPermission

@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ('organization_member', 'get_permissions', 'assigned_at')
    search_fields = ('organization_member__user__email', 'permissions__name')
    list_filter = ('organization_member__organization',)
    filter_horizontal = ('permissions',)

    def get_permissions(self, obj):
        return ", ".join([p.name for p in obj.permissions.all()])
    get_permissions.short_description = 'Direct Permissions'
