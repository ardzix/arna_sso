import pyotp
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.contrib.auth import authenticate
from authentication.models import User
from authentication.serializers import UserSerializer
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
            refresh = RefreshToken.for_user(user)

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
            # Emit signal to log login asynchronously
            user_logged_in.send(
                sender=self.__class__, user=user, metadata={"email": user.email}
            )

            if user.mfa_secret:
                # Emit signal for MFA login attempt
                mfa_login_attempt.send(
                    sender=self.__class__, user=user, metadata={"mfa_required": True}
                )

                # MFA is enabled, send response to prompt MFA token
                return Response(
                    {
                        "mfa_required": True,
                        "message": "MFA is required. Please provide your MFA token.",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                # MFA is not enabled, return the JWT tokens
                refresh = RefreshToken.for_user(user)
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
    @swagger_auto_schema(
        operation_description="Verify MFA token and return JWT tokens if successful.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="User email"
                ),
                "mfa_token": openapi.Schema(
                    type=openapi.TYPE_STRING, description="MFA token"
                ),
            },
            required=["email", "mfa_token"],
        ),
        responses={
            200: openapi.Response(
                description="MFA token verified, JWT tokens returned",
                examples={
                    "application/json": {
                        "refresh": "eyJhbGciOiJIUzI1...",
                        "access": "eyJhbGciOiJIUzI1...",
                    }
                },
            ),
            400: "Invalid MFA token or credentials",
            404: "User not found",
        },
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        mfa_token = request.data.get("mfa_token")

        try:
            user = User.objects.get(email=email)

            # Verify the provided MFA token
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(mfa_token):
                # MFA verified, return the JWT tokens
                refresh = RefreshToken.for_user(user)

                # Emit signal for successful MFA verification
                mfa_verified.send(
                    sender=self.__class__, user=user, metadata={"mfa_token": mfa_token}
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
                    {"error": "Invalid MFA token or credentials"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except User.DoesNotExist:
            return Response(
                {"error": "Invalid MFA token or credentials"},
                status=status.HTTP_404_NOT_FOUND,
            )