import pyotp
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import UntypedToken
from django.contrib.auth import authenticate
from django.utils.timezone import now
from authentication.models import User
from authentication.serializers import UserSerializer, MyTokenObtainPairSerializer, PreAuthTokenSerializer
from datetime import timedelta
from .libs.utils import generate_otp
from .signals import send_otp_email
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings
from authentication.serializers import PasswordResetRequestSerializer, PasswordResetConfirmSerializer, ChangePasswordSerializer
from user_profile.models import UserProfile
from django.core.cache import cache

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from authentication.signals import (
    user_registered,
    user_logged_in,
    user_logged_out,
    mfa_setup,
    user_token_refreshed,
    mfa_login_attempt,
    mfa_verified,
)
from google.oauth2 import id_token
from google.auth.transport import requests

class RegisterView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated users to register

    @swagger_auto_schema(
        request_body=UserSerializer,
        operation_description="Register a new user.",
        responses={
            201: openapi.Response(
                description="User registered successfully",
                examples={
                    "application/json": {
                        "refresh": "eyJhbGciOiJIUzI1...",
                        "access": "eyJhbGciOiJIUzI1...",
                    }
                },
            ),
            400: "Bad Request",
        },
    )
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = MyTokenObtainPairSerializer.get_token(user)

            # Emit signal to log the registration asynchronously
            user_registered.send(
                sender=self.__class__, user=user, metadata={"email": user.email}
            )

            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    """
    This will handle login and return access and refresh tokens if MFA is not enabled.
    """
    serializer_class = MyTokenObtainPairSerializer

    @swagger_auto_schema(
        operation_description="Login a user and return access and refresh tokens.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="User email"
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="User password"
                ),
            },
            required=["email", "password"],
        ),
        responses={
            200: openapi.Response(
                description="JWT tokens returned",
                examples={
                    "application/json": {
                        "refresh": "eyJhbGciOiJIUzI1...",
                        "access": "eyJhbGciOiJIUzI1...",
                    }
                },
            ),
            400: "Invalid credentials",
        },
    )
    def post(self, request):
        response = super().post(request)

        if response.status_code == 200:
            user = User.objects.get(email=request.data.get("email"))
            # Emit signal to log login asynchronously
            user_logged_in.send(
                sender=self.__class__, user=user, metadata={"email": user.email}
            )

        return response


class LogoutView(APIView):
    @swagger_auto_schema(
        operation_description="Logout user by blacklisting the refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "refresh": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Refresh token"
                )
            },
            required=["refresh"],
        ),
        responses={205: "Logout successful", 400: "Bad Request"},
    )
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            user = request.user
            # Emit signal to log logout asynchronously
            user_logged_out.send(
                sender=self.__class__,
                user=user,
                metadata={"refresh_token": refresh_token},
            )

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class RefreshTokenView(TokenRefreshView):
    """
    This view will handle refreshing access tokens.
    """

    """
    This view will handle refreshing access tokens.
    """

    @swagger_auto_schema(
        operation_description="Refresh JWT access token using a refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "refresh": openapi.Schema(
                    type=openapi.TYPE_STRING, description="The refresh token to use"
                ),
            },
            required=["refresh"],
        ),
        responses={
            200: openapi.Response(
                description="New access token",
                examples={
                    "application/json": {
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                    }
                },
            ),
            400: "Invalid token or token expired",
        },
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            # Emit signal for token refresh action
            user = request.user
            user_token_refreshed.send(
                sender=self.__class__,
                user=user,
                metadata={"refresh_token": request.data.get("refresh")},
            )

        return response


class SetMFAView(APIView):
    @swagger_auto_schema(
        operation_description="Set up MFA for the user and return the MFA secret and QR code URL.",
        responses={
            200: openapi.Response(
                description="MFA secret and QR code URL returned",
                examples={
                    "application/json": {
                        "mfa_secret": "SECRET_CODE",
                        "qr_code_url": "otpauth://totp/YourApp:testuser@example.com?secret=SECRET_CODE&issuer=YourApp",
                    }
                },
            )
        },
    )
    def post(self, request):
        user = request.user
        user.generate_mfa_secret()
        totp = pyotp.TOTP(user.mfa_secret)

        # Emit signal for MFA setup action
        mfa_setup.send(
            sender=self.__class__, user=user, metadata={"mfa_secret": user.mfa_secret}
        )

        return Response(
            {
                "mfa_secret": user.mfa_secret,
                "qr_code_url": totp.provisioning_uri(user.email, issuer_name="YourApp"),
            }
        )


class MFAAwareLoginView(APIView):
    @swagger_auto_schema(
        operation_description="Handle MFA-aware login. Prompt for MFA if enabled.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="User email"
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="User password"
                ),
            },
            required=["email", "password"],
        ),
        responses={
            200: openapi.Response(
                description="MFA required or JWT tokens returned",
                examples={
                    "application/json": {
                        "mfa_required": True,
                        "message": "MFA is required. Please provide your MFA token.",
                    }
                },
            ),
            400: "Invalid credentials",
        },
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(request, email=email, password=password)

        if user is not None:
            if user.mfa_secret:
                # Emit signal for MFA login attempt
                mfa_login_attempt.send(
                    sender=self.__class__, user=user, metadata={"mfa_required": True}
                )

                # MFA is enabled, send response to prompt MFA token
                pre_auth_token = PreAuthTokenSerializer.get_token(user)
                return Response(
                    {
                        "mfa_required": True,
                        "message": "MFA is required. Please provide your MFA token.",
                        "token": pre_auth_token,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                # MFA is not enabled, return the JWT tokens
                refresh = MyTokenObtainPairSerializer.get_token(user)
                # Emit signal to log login asynchronously
                user_logged_in.send(
                    sender=self.__class__, user=user, metadata={"email": user.email}
                )
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
        else:
            return Response(
                {"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
            )


class MFAVerifyView(APIView):
    throttle_scope = 'mfa_verify'
    
    @swagger_auto_schema(
        operation_description="Verify MFA token using a Pre-Auth Token from the previous step.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "token": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Pre-Auth Token (received from Login step)"
                ),
                "mfa_token": openapi.Schema(
                    type=openapi.TYPE_STRING, description="6-digit MFA Code"
                ),
            },
            required=["token", "mfa_token"],
        ),
        responses={
            200: openapi.Response(
                description="MFA verified, JWT tokens returned",
                examples={
                    "application/json": {
                        "refresh": "eyJ...",
                        "access": "eyJ...",
                    }
                },
            ),
            400: "Invalid Token or Code",
            401: "Token Expired or Invalid",
        },
    )
    def post(self, request, *args, **kwargs):
        pre_auth_token = request.data.get("token")
        mfa_code = request.data.get("mfa_token")

        if not pre_auth_token or not mfa_code:
             return Response(
                {"error": "Missing token or MFA code"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # 1. Validate the Pre-Auth Token
            valid_data = UntypedToken(pre_auth_token)
            
            # Check token type
            if valid_data.get("type") != "pre_auth":
                 return Response(
                    {"error": "Invalid token type"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            user_id = valid_data.get("user_id")
            user = User.objects.get(id=user_id)

            # 2. Verify the TOTP Code Check Cache for Replay Attack
            cache_key = f"mfa_used_{user.id}_{mfa_code}"
            if cache.get(cache_key):
                 return Response(
                    {"error": "Invalid MFA code (Token reused)"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            totp = pyotp.TOTP(user.mfa_secret)
            # valid_window=1 allows current time, +30s, and -30s (total 90s window) to handle clock drift
            if totp.verify(mfa_code, valid_window=1):
                # Mark token as used in cache for 90 seconds (covering the valid window)
                cache.set(cache_key, True, timeout=90)
                
                # MFA verified -> ISSUE REAL TOKENS
                refresh = MyTokenObtainPairSerializer.get_token(user)
                mfa_verified.send(
                    sender=self.__class__, user=user, metadata={"mfa_token": mfa_code}
                )
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"error": "Invalid MFA code"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except Exception as e:
            # Catch token errors (expired, invalid signature)
            print(f"MFA Error: {e}")
            return Response(
                {"error": "Invalid or expired session. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify the email with OTP.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit OTP'),
            },
            required=['email', 'otp']
        ),
        responses={
            200: openapi.Response(description="Email verified successfully."),
            400: "Invalid OTP or expired OTP.",
            404: "User not found.",
        },
    )
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        try:
            user = User.objects.get(email=email)
            if user.otp == otp and user.otp_expiration > now():
                user.is_active = True
                user.otp = None  # Clear OTP after successful verification
                user.otp_expiration = None
                user.save()

                return Response({"message": "Email verified successfully."})
            return Response({"error": "Invalid OTP or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class ResendOTPView(APIView):
    @swagger_auto_schema(
        operation_description="Resend OTP to user's email. Can only be done 5 minutes after the last OTP was sent.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
            },
            required=['email'],
        ),
        responses={
            200: openapi.Response(description="OTP resent successfully."),
            400: "Bad Request (e.g., OTP sent too recently, user already verified)",
            404: "User not found",
        },
    )
    def post(self, request):
        # Functionality remains the same as above
        email = request.data.get("email")

        try:
            user = User.objects.get(email=email)

            if user.is_active:
                return Response({"error": "User is already verified."}, status=status.HTTP_400_BAD_REQUEST)

            if user.last_otp_sent and now() - user.last_otp_sent < timedelta(minutes=5):
                time_remaining = 5 - (now() - user.last_otp_sent).seconds // 60
                return Response(
                    {"error": f"Please wait {time_remaining} minutes before resending OTP."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            from django_q.tasks import async_task
            from authentication.signals import send_otp_email as send_otp
            async_task(send_otp, user.email)

            return Response({"message": "OTP resent successfully."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Request a password reset OTP email.",
        request_body=PasswordResetRequestSerializer,
        responses={
            200: openapi.Response(description="Password reset OTP sent if user exists."),
        },
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
            # Use async_task to send OTP email, matching registration flow
            from django_q.tasks import async_task
            from authentication.signals import send_otp_email as send_otp
            async_task(send_otp, user.email)
            # Audit log
            from audit_logging.models import AuditLog
            AuditLog.objects.create(user=user, action="password_reset_requested", metadata={"email": email})
        except User.DoesNotExist:
            pass  # Do not reveal if user exists
        return Response({"message": "If the email exists, a password reset OTP has been sent."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Confirm password reset with OTP and set new password.",
        request_body=PasswordResetConfirmSerializer,
        responses={
            200: openapi.Response(description="Password has been reset successfully."),
            400: "Invalid OTP or user.",
        },
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        new_password = serializer.validated_data["new_password"]
        try:
            user = User.objects.get(email=email)
            if user.otp == otp and user.otp_expiration and user.otp_expiration > now():
                user.set_password(new_password)
                user.otp = None
                user.otp_expiration = None
                user.save()
                # Audit log
                from audit_logging.models import AuditLog
                AuditLog.objects.create(user=user, action="password_reset_confirmed", metadata={})
                return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid OTP or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "Invalid OTP or user."}, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    permission_classes = [ ]  # Will use IsAuthenticated below

    @swagger_auto_schema(
        operation_description="Change password for authenticated user.",
        request_body=ChangePasswordSerializer,
        responses={
            200: openapi.Response(description="Password changed successfully."),
            400: "Invalid old password.",
        },
    )
    def post(self, request):
        from rest_framework.permissions import IsAuthenticated
        self.permission_classes = [IsAuthenticated]
        self.check_permissions(request)
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]
        if not user.check_password(old_password):
            return Response({"error": "Invalid old password."}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()
        # Audit log
        from audit_logging.models import AuditLog
        AuditLog.objects.create(user=user, action="password_changed", metadata={})
        return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)

class GoogleLoginView(APIView):
    @swagger_auto_schema(
        operation_description="Handle Google Login.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "token": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Google Token"
                ),
            },
            required=["token"],
        ),
    )

    def post(self, request, *args, **kwargs):
        token = request.data.get("token")

        if not token:
            return Response({"error": "Missing Google token"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Verify token
            idinfo = id_token.verify_oauth2_token(token, requests.Request())
            email = idinfo.get("email")
            picture = idinfo.get("picture")
            name = idinfo.get("name")

            if not email:
                return Response({"error": "Google token invalid, email missing"}, status=status.HTTP_400_BAD_REQUEST)

            # Get or create user
            user, _ = User.objects.get_or_create(email=email)

            # Update or create UserProfile in one step
            profile, _ = UserProfile.objects.update_or_create(
                user=user,
                defaults={
                    "profile_picture": picture or "",
                    "full_name": name or "",
                },
            )

            # Check if MFA is enabled
            if user.mfa_secret:
                # Emit signal for MFA login attempt
                mfa_login_attempt.send(
                    sender=self.__class__, user=user, metadata={"mfa_required": True, "method": "google"}
                )
                pre_auth_token = PreAuthTokenSerializer.get_token(user)
                return Response(
                    {
                        "mfa_required": True,
                        "message": "MFA is required. Please provide your MFA token.",
                        "token": pre_auth_token,
                        "email": user.email,
                    },
                    status=status.HTTP_200_OK,
                )

            # Issue JWT tokens
            refresh = MyTokenObtainPairSerializer.get_token(user)
            user_logged_in.send(
                sender=self.__class__, user=user, metadata={"email": email}
            )
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "email":email,
                    "full_name": profile.full_name,
                },
                status=status.HTTP_200_OK,
            )

        except ValueError:
            return Response({"error": "Invalid Google token"}, status=status.HTTP_400_BAD_REQUEST)

from django.shortcuts import render

def homepage(request):
    return render(request, 'homepage.html')

class ManageUserView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get details of the currently authenticated user.",
        responses={
            200: UserSerializer(),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Update details of the currently authenticated user.",
        request_body=UserSerializer,
        responses={
            200: UserSerializer(),
            400: "Bad Request",
            401: "Unauthorized",
        },
    )
    def patch(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)