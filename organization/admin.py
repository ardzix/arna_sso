from django.contrib import admin
from .models import Organization

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'package_type', 'created_at', 'updated_at')
    search_fields = ('name', 'owner__email', 'package_type')
    list_filter = ('package_type', 'created_at')

from .models import OrganizationMember

@admin.register(OrganizationMember)
class OrganizationMemberAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization', 'is_session_active', 'joined_at')
    list_filter = ('organization', 'is_session_active')
    search_fields = ('user__email', 'organization__name')
    list_select_related = ('user', 'organization')
