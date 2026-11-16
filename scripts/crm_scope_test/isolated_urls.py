from django.urls import path
from authentication.sso_views import SSOAuthorizeCodeView, SSOTokenExchangeView
urlpatterns = [
    path('authorize/', SSOAuthorizeCodeView.as_view(), name='sso_authorize_code'),
    path('exchange/', SSOTokenExchangeView.as_view(), name='sso_token_exchange'),
]
