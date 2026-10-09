from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from authentication.views import homepage
from authentication.sso_views import sso_login_page
from authentication.admin_mfa import patch_admin_site
from sso_service.swagger_info import api_info
from authentication.gift_registration import TrustedWhatsAppRegistrationView, RegistrationServiceTokenView
from sso_service.health import live, ready

patch_admin_site()

schema_view = get_schema_view(
    api_info,
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('health/live', live, name='health_live'),
    path('health/ready', ready, name='health_ready'),
    path('api/v1/registrations/service-token/', RegistrationServiceTokenView.as_view(), name='registration_service_token'),
    path('api/v1/registrations/whatsapp/', TrustedWhatsAppRegistrationView.as_view(), name='trusted_whatsapp_registration'),
    path('admin/', admin.site.urls),
    path('login/', sso_login_page, name='sso_login_page'),
    path('api/auth/', include('authentication.urls')),
    path('api/organizations/', include('organization.urls')),
    path('api/', include('user_profile.urls')),
    path('api/iam/', include('iam.urls')),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('', homepage, name='homepage'),
]
