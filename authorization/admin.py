from django.contrib import admin
from .models import Role, Permission

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at', 'updated_at')
    search_fields = ('name',)
    list_filter = ('created_at',)
    readonly_fields = ('created_at', 'updated_at')  # Make timestamps read-only

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('name', 'module', 'created_at', 'updated_at')
    search_fields = ('name', 'module')
    list_filter = ('module', 'created_at')
    readonly_fields = ('created_at', 'updated_at')  # Make timestamps read-only
