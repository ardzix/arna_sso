from django.contrib import admin
from .models import OAuthProvider, OAuthToken

@admin.register(OAuthProvider)
class OAuthProviderAdmin(admin.ModelAdmin):
    list_display = ('name', 'client_id', 'authorization_url', 'token_url')
    search_fields = ('name', 'client_id')

@admin.register(OAuthToken)
class OAuthTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'provider', 'access_token', 'created_at')
    search_fields = ('user__email', 'provider__name')
    list_filter = ('provider',)
