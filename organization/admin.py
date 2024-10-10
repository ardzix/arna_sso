from django.contrib import admin
from .models import Organization

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'package_type', 'created_at', 'updated_at')
    search_fields = ('name', 'owner__email', 'package_type')
    list_filter = ('package_type', 'created_at')
