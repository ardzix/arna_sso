from django.contrib import admin
from .models import AuditLog

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'created_at')
    search_fields = ('user__email', 'action')
    list_filter = ('action', 'created_at')
    readonly_fields = ('user', 'action', 'metadata', 'created_at')  # Make fields read-only
