from django.urls import path
from rest_framework_simplejwt.views import TokenVerifyView
from .views import RegisterView, MFAAwareLoginView, LogoutView, RefreshTokenView, SetMFAView, MFAVerifyView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('mfa/set/', SetMFAView.as_view(), name='set_mfa'),
    path('login/', MFAAwareLoginView.as_view(), name='login'),  # Handles the first step (email/password)
    path('mfa/verify/', MFAVerifyView.as_view(), name='mfa_verify'),  # Handles the second step (MFA verification)
]
