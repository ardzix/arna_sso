from django.urls import path
from rest_framework_simplejwt.views import TokenVerifyView
from .views import (
    RegisterView,
    MFAAwareLoginView,
    LogoutView,
    RefreshTokenView,
    SetMFAView,
    MFAVerifyView,
    VerifyEmailView,
    ResendOTPView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    ChangePasswordView,
)
from .wa_views import (
    WASendLinkOTPView,
    WAVerifyLinkView,
    WARegisterRequestView,
    WARegisterVerifyView,
    WASendOTPView,
    WAVerifyOTPView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('mfa/set/', SetMFAView.as_view(), name='set_mfa'),
    path('login/', MFAAwareLoginView.as_view(), name='login'),
    path('mfa/verify/', MFAVerifyView.as_view(), name='mfa_verify'),
    path("verify-email/", VerifyEmailView.as_view(), name="verify_email"),
    path("resend-email-otp/", ResendOTPView.as_view(), name="resend_email_otp"),
    path("password-reset-request/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    
    # WhatsApp OTP endpoints
    path('wa/send-link-otp/', WASendLinkOTPView.as_view(), name='wa_send_link_otp'),
    path('wa/verify-link/', WAVerifyLinkView.as_view(), name='wa_verify_link'),
    path('wa/register-request/', WARegisterRequestView.as_view(), name='wa_register_request'),
    path('wa/register-verify/', WARegisterVerifyView.as_view(), name='wa_register_verify'),
    path('wa/send-otp/', WASendOTPView.as_view(), name='wa_send_otp'),
    path('wa/verify-otp/', WAVerifyOTPView.as_view(), name='wa_verify_otp'),
]
