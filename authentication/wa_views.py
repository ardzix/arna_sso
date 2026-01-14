from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.timezone import now
from datetime import timedelta
from django_q.tasks import async_task

from authentication.models import User
from authentication.serializers import (
    WASendLinkOTPSerializer,
    WAVerifyLinkSerializer,
    WARegisterRequestSerializer,
    WARegisterVerifySerializer,
    WASendOTPSerializer,
    WAVerifyOTPSerializer,
    WAReverseSendLinkOTPSerializer,
    WAReverseRegisterRequestSerializer,
    WAReverseSendOTPSerializer,
    PreAuthTokenSerializer,
)
from authentication.libs.utils import (
    normalize_phone_number,
    send_otp_whatsapp,
    send_otp_to_n8n,
    generate_otp,
)

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class WASendLinkOTPView(APIView):
    """
    Link WhatsApp number to existing authenticated user account.
    Send OTP to verify phone ownership.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=WASendLinkOTPSerializer,
        operation_description="Send OTP to link WhatsApp number to authenticated user.",
        responses={
            200: openapi.Response(description="OTP sent to WhatsApp"),
            400: "Invalid phone number or phone already in use",
            429: "Too many requests, wait before resending",
        },
    )
    def post(self, request):
        serializer = WASendLinkOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            return Response(
                {"error": "Invalid phone number format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        
        # Check cooldown
        if user.last_otp_sent and now() - user.last_otp_sent < timedelta(minutes=5):
            time_remaining = 5 - (now() - user.last_otp_sent).seconds // 60
            return Response(
                {"error": f"Please wait {time_remaining} minutes before resending OTP."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        
        # Check if phone already used by another user
        existing_user = User.objects.filter(phone_number=phone).exclude(id=user.id).first()
        if existing_user:
            return Response(
                {"error": "Phone number already linked to another account"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate and send OTP
        otp = generate_otp()
        user.otp = otp
        user.otp_expiration = now() + timedelta(minutes=10)
        user.last_otp_sent = now()
        user.pending_phone = phone
        user.save()
        
        # Send OTP via WhatsApp asynchronously
        async_task(send_otp_whatsapp, phone, otp)
        
        return Response(
            {"message": "OTP sent to WhatsApp", "phone": phone},
            status=status.HTTP_200_OK
        )


class WAVerifyLinkView(APIView):
    """
    Verify OTP and link WhatsApp number to user account.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=WAVerifyLinkSerializer,
        operation_description="Verify OTP to link WhatsApp number.",
        responses={
            200: openapi.Response(description="Phone number linked successfully"),
            400: "Invalid or expired OTP",
        },
    )
    def post(self, request):
        serializer = WAVerifyLinkSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        otp = serializer.validated_data['otp']
        user = request.user
        
        if not user.pending_phone:
            return Response(
                {"error": "No pending phone number to verify"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if user.otp == otp and user.otp_expiration and user.otp_expiration > now():
            user.phone_number = user.pending_phone
            user.phone_verified = True
            user.pending_phone = None
            user.otp = None
            user.otp_expiration = None
            user.save()
            
            return Response(
                {"message": "Phone number linked successfully", "phone": user.phone_number},
                status=status.HTTP_200_OK
            )
        
        return Response(
            {"error": "Invalid or expired OTP"},
            status=status.HTTP_400_BAD_REQUEST
        )


class WARegisterRequestView(APIView):
    """
    Register new user with WhatsApp number (with optional email).
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=WARegisterRequestSerializer,
        operation_description="Register new user with WhatsApp. Send OTP for verification.",
        responses={
            200: openapi.Response(description="OTP sent to WhatsApp"),
            400: "Invalid data or phone already in use",
        },
    )
    def post(self, request):
        serializer = WARegisterRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        email = serializer.validated_data.get('email', '').strip()
        
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            return Response(
                {"error": "Invalid phone number format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if phone already exists
        if User.objects.filter(phone_number=phone).exists():
            return Response(
                {"error": "Phone number already registered"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Determine email: use provided or placeholder
        if not email:
            email = f"wa_{phone}@arnatech.local"
        
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "Email already registered"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create user (inactive)
        user = User.objects.create_user(email=email, password=None)
        user.is_active = False
        user.phone_number = phone
        user.phone_verified = False
        
        # Generate OTP
        otp = generate_otp()
        user.otp = otp
        user.otp_expiration = now() + timedelta(minutes=10)
        user.last_otp_sent = now()
        user.save()
        
        # Send OTP via WhatsApp asynchronously
        async_task(send_otp_whatsapp, phone, otp)
        
        return Response(
            {"message": "OTP sent to WhatsApp", "phone": phone},
            status=status.HTTP_200_OK
        )


class WARegisterVerifyView(APIView):
    """
    Verify OTP and activate user account registered via WhatsApp.
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=WARegisterVerifySerializer,
        operation_description="Verify OTP to activate account and receive JWT tokens.",
        responses={
            200: openapi.Response(
                description="Account activated, JWT tokens returned",
                examples={
                    "application/json": {
                        "message": "Account activated successfully",
                        "refresh": "eyJhbGciOiJIUzI1...",
                        "access": "eyJhbGciOiJIUzI1...",
                    }
                },
            ),
            400: "Invalid or expired OTP",
            404: "User not found",
        },
    )
    def post(self, request):
        serializer = WARegisterVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        otp = serializer.validated_data['otp']
        
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            return Response(
                {"error": "Invalid phone number format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(phone_number=phone)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if user.otp == otp and user.otp_expiration and user.otp_expiration > now():
            user.is_active = True
            user.phone_verified = True
            user.otp = None
            user.otp_expiration = None
            user.save()
            
            # Issue JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response(
                {
                    "message": "Account activated successfully",
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK
            )
        
        return Response(
            {"error": "Invalid or expired OTP"},
            status=status.HTTP_400_BAD_REQUEST
        )


class WASendOTPView(APIView):
    """
    Send OTP to WhatsApp for login (existing verified phone).
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=WASendOTPSerializer,
        operation_description="Send OTP to WhatsApp for login.",
        responses={
            200: openapi.Response(description="OTP sent if phone is registered"),
        },
    )
    def post(self, request):
        serializer = WASendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            # Generic response for security
            return Response(
                {"message": "If the phone number is registered, OTP has been sent."},
                status=status.HTTP_200_OK
            )
        
        try:
            user = User.objects.get(phone_number=phone, phone_verified=True)
            
            # Check cooldown
            if user.last_otp_sent and now() - user.last_otp_sent < timedelta(minutes=5):
                return Response(
                    {"message": "If the phone number is registered, OTP has been sent."},
                    status=status.HTTP_200_OK
                )
            
            # Generate and send OTP
            otp = generate_otp()
            user.otp = otp
            user.otp_expiration = now() + timedelta(minutes=10)
            user.last_otp_sent = now()
            user.save()
            
            # Send OTP via WhatsApp asynchronously
            async_task(send_otp_whatsapp, phone, otp)
        except User.DoesNotExist:
            pass  # Don't reveal if phone exists
        
        return Response(
            {"message": "If the phone number is registered, OTP has been sent."},
            status=status.HTTP_200_OK
        )


class WAVerifyOTPView(APIView):
    """
    Verify OTP and login via WhatsApp.
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=WAVerifyOTPSerializer,
        operation_description="Verify OTP and receive JWT tokens for login.",
        responses={
            200: openapi.Response(
                description="Login successful, JWT tokens returned",
                examples={
                    "application/json": {
                        "refresh": "eyJhbGciOiJIUzI1...",
                        "access": "eyJhbGciOiJIUzI1...",
                    }
                },
            ),
            400: "Invalid or expired OTP",
            404: "User not found",
        },
    )
    def post(self, request):
        serializer = WAVerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        otp = serializer.validated_data['otp']
        
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            return Response(
                {"error": "Invalid phone number format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(phone_number=phone)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if user.otp == otp and user.otp_expiration and user.otp_expiration > now():
            # Clear OTP
            user.otp = None
            user.otp_expiration = None
            # Activate user and verify phone (OTP verification means phone is valid)
            user.is_active = True
            user.phone_verified = True
            user.save()
            
            # Check if MFA is enabled
            if user.mfa_secret:
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
            refresh = RefreshToken.for_user(user)
            
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK
            )
        
        return Response(
            {"error": "Invalid or expired OTP"},
            status=status.HTTP_400_BAD_REQUEST
        )


# ============================================================================
# Reverse WA OTP Views (n8n webhook method - user must initiate chat)
# ============================================================================

class WAReverseSendLinkOTPView(APIView):
    """
    Link WhatsApp number to existing authenticated user account using reverse OTP.
    Send OTP data to n8n webhook instead of pushing via WAHA.
    User must initiate chat to receive OTP.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=WAReverseSendLinkOTPSerializer,
        operation_description="Send OTP data to n8n webhook for reverse WA authentication. User must initiate chat.",
        responses={
            200: openapi.Response(description="OTP data sent to n8n webhook"),
            400: "Invalid phone number or phone already in use",
            429: "Too many requests, wait before resending",
        },
    )
    def post(self, request):
        serializer = WAReverseSendLinkOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            return Response(
                {"error": "Invalid phone number format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        
        # Check cooldown
        if user.last_otp_sent and now() - user.last_otp_sent < timedelta(minutes=5):
            time_remaining = 5 - (now() - user.last_otp_sent).seconds // 60
            return Response(
                {"error": f"Please wait {time_remaining} minutes before resending OTP."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        
        # Check if phone already used by another user
        existing_user = User.objects.filter(phone_number=phone).exclude(id=user.id).first()
        if existing_user:
            return Response(
                {"error": "Phone number already linked to another account"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate and send OTP
        otp = generate_otp()
        user.otp = otp
        user.otp_expiration = now() + timedelta(minutes=10)
        user.last_otp_sent = now()
        user.pending_phone = phone
        user.save()
        
        # Send OTP data to n8n webhook (reverse method - user must initiate chat)
        async_task(send_otp_to_n8n, phone, otp)
        
        return Response(
            {
                "message": "OTP data sent to n8n. Please initiate chat via WhatsApp link.",
                "phone": phone,
                "method": "reverse"
            },
            status=status.HTTP_200_OK
        )


class WAReverseRegisterRequestView(APIView):
    """
    Register new user with WhatsApp number using reverse OTP (n8n webhook method).
    Send OTP data to n8n instead of pushing via WAHA.
    User must initiate chat to receive OTP.
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=WAReverseRegisterRequestSerializer,
        operation_description="Register new user with WhatsApp using reverse OTP. Send OTP data to n8n webhook.",
        responses={
            200: openapi.Response(description="OTP data sent to n8n webhook"),
            400: "Invalid data or phone already in use",
        },
    )
    def post(self, request):
        serializer = WAReverseRegisterRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        email = serializer.validated_data.get('email', '').strip()
        
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            return Response(
                {"error": "Invalid phone number format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if phone already exists
        if User.objects.filter(phone_number=phone).exists():
            return Response(
                {"error": "Phone number already registered"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Determine email: use provided or placeholder
        if not email:
            email = f"wa_{phone}@arnatech.local"
        
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "Email already registered"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create user (inactive)
        user = User.objects.create_user(email=email, password=None)
        user.is_active = False
        user.phone_number = phone
        user.phone_verified = False
        
        # Generate OTP
        otp = generate_otp()
        user.otp = otp
        user.otp_expiration = now() + timedelta(minutes=10)
        user.last_otp_sent = now()
        user.save()
        
        # Send OTP data to n8n webhook (reverse method - user must initiate chat)
        async_task(send_otp_to_n8n, phone, otp)
        
        return Response(
            {
                "message": "OTP data sent to n8n. Please initiate chat via WhatsApp link.",
                "phone": phone,
                "method": "reverse"
            },
            status=status.HTTP_200_OK
        )


class WAReverseSendOTPView(APIView):
    """
    Send OTP data to n8n webhook for login/register using reverse WA OTP authentication.
    User must initiate chat to receive OTP.
    If phone number is not registered, automatically register the user.
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=WAReverseSendOTPSerializer,
        operation_description="Send OTP data to n8n webhook for reverse WA login/register. User must initiate chat. Auto-registers if phone not found.",
        responses={
            200: openapi.Response(description="OTP data sent to n8n webhook"),
        },
    )
    def post(self, request):
        serializer = WAReverseSendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_raw = serializer.validated_data['phone']
        phone = normalize_phone_number(phone_raw)
        
        if not phone:
            return Response(
                {"error": "Invalid phone number format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Try to get user by phone number (regardless of phone_verified status)
        user = User.objects.filter(phone_number=phone).first()
        
        # If user doesn't exist, auto-register
        if not user:
            # Generate placeholder email
            email = f"wa_{phone}@arnatech.local"
            
            # Check if email already exists (edge case)
            if User.objects.filter(email=email).exists():
                # If email exists, try with phone in email
                email = f"wa_{phone}_{now().timestamp()}@arnatech.local"
            
            # Create new user (inactive, phone_verified=False)
            user = User.objects.create_user(email=email, password=None)
            user.is_active = False
            user.phone_number = phone
            user.phone_verified = False
        
        # Check cooldown
        if user.last_otp_sent and now() - user.last_otp_sent < timedelta(minutes=5):
            return Response(
                {"message": "OTP data has been sent to n8n. Please wait before requesting again."},
                status=status.HTTP_200_OK
            )
        
        # Generate and send OTP (regardless of phone_verified status)
        otp = generate_otp()
        user.otp = otp
        user.otp_expiration = now() + timedelta(minutes=10)
        user.last_otp_sent = now()
        user.save()
        
        # Send OTP data to n8n webhook (reverse method - user must initiate chat)
        async_task(send_otp_to_n8n, phone, otp)
        
        return Response(
            {"message": "OTP data has been sent to n8n. Please initiate chat via WhatsApp link."},
            status=status.HTTP_200_OK
        )

