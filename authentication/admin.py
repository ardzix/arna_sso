from django.contrib import admin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        'id','email', 'is_active', 'is_staff', 'mfa_enabled', 'date_joined', 'last_otp_sent'
    )
    list_filter = (
        'is_active', 'is_staff', 'mfa_enabled', 'date_joined'
    )
    search_fields = ('email', 'id')
    ordering = ('-date_joined',)
    readonly_fields = ('id', 'date_joined', 'last_otp_sent', 'otp_expiration')
    list_editable = ('is_active', 'is_staff')
    fieldsets = (
        (None, {
            'fields': ('id', 'email', 'password', 'is_active', 'is_staff', 'date_joined')
        }),
        ('MFA & OTP', {
            'fields': ('mfa_enabled', 'mfa_secret', 'otp', 'otp_expiration', 'last_otp_sent')
        }),
        ('Profile', {
            'fields': ('profile_data',)
        }),
        ('Permissions', {
            'fields': ('groups', 'user_permissions')
        }),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_active', 'is_staff', 'mfa_enabled'),
        }),
    )
