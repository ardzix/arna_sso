from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User,
    CorsAllowedOrigin,
    ServiceAccount,
    SSOAllowedRedirectURI,
    SSOAuthorizationCode,
    DeviceAuthorizationGrant,
    DeviceRefreshCredential,
    DeviceRegistration,
)

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = (
        'id', 'email', 'phone_number', 'phone_verified', 'is_active', 
        'is_staff', 'mfa_enabled', 'date_joined'
    )
    list_filter = (
        'is_active', 'is_staff', 'mfa_enabled', 'phone_verified', 'date_joined'
    )
    search_fields = ('email', 'id', 'phone_number', 'pending_phone')
    ordering = ('-date_joined',)
    readonly_fields = ('id', 'date_joined', 'last_otp_sent', 'otp_expiration')
    list_editable = ('is_active', 'is_staff')
    
    fieldsets = (
        (None, {
            'fields': ('id', 'email', 'password', 'is_active', 'is_staff', 'date_joined')
        }),
        ('WhatsApp/Phone', {
            'fields': ('phone_number', 'phone_verified', 'pending_phone'),
            'description': 'WhatsApp OTP authentication fields'
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


@admin.register(CorsAllowedOrigin)
class CorsAllowedOriginAdmin(admin.ModelAdmin):
    list_display = ("origin", "is_active", "updated_at")
    list_filter = ("is_active", "updated_at")
    search_fields = ("origin", "notes")
    readonly_fields = ("created_at", "updated_at")
    fields = ("origin", "is_active", "notes", "created_at", "updated_at")


@admin.register(SSOAllowedRedirectURI)
class SSOAllowedRedirectURIAdmin(admin.ModelAdmin):
    list_display = ("client_id", "redirect_uri", "is_active", "updated_at")
    list_filter = ("client_id", "is_active", "updated_at")
    search_fields = ("client_id", "redirect_uri", "notes")
    readonly_fields = ("created_at", "updated_at")
    fields = (
        "client_id",
        "redirect_uri",
        "is_active",
        "notes",
        "created_at",
        "updated_at",
    )


@admin.register(ServiceAccount)
class ServiceAccountAdmin(admin.ModelAdmin):
    list_display = ("name", "client_id", "organization_id", "is_active", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("name", "client_id", "organization_id")
    readonly_fields = ("id", "client_secret_hash", "created_at", "updated_at")


@admin.register(SSOAuthorizationCode)
class SSOAuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ("client_id", "user", "redirect_uri", "expires_at", "used_at")
    list_filter = ("client_id", "expires_at", "used_at")
    search_fields = ("client_id", "redirect_uri", "user__email")
    readonly_fields = (
        "id",
        "code_hash",
        "user",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "created_at",
        "expires_at",
        "used_at",
    )


@admin.register(DeviceRegistration)
class DeviceRegistrationAdmin(admin.ModelAdmin):
    list_display = ("display_name", "client_id", "organization", "tenant_id", "audience", "is_active", "last_seen_at")
    list_filter = ("is_active", "audience")
    search_fields = ("display_name", "client_id", "tenant_id")
    readonly_fields = ("id", "created_at", "updated_at", "approved_at", "last_seen_at")


@admin.register(DeviceAuthorizationGrant)
class DeviceAuthorizationGrantAdmin(admin.ModelAdmin):
    list_display = ("client_id", "device_name", "tenant_id", "expires_at", "approved_at", "consumed_at", "denied_at")
    search_fields = ("client_id", "device_name", "tenant_id")
    readonly_fields = ("id", "device_code_hash", "user_code_hash", "created_at")


@admin.register(DeviceRefreshCredential)
class DeviceRefreshCredentialAdmin(admin.ModelAdmin):
    list_display = ("registration", "expires_at", "used_at", "revoked_at")
    readonly_fields = ("id", "token_hash", "created_at")
