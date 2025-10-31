from rest_framework import serializers
from authentication.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']  # Ensure both email and password are included
        extra_kwargs = {
            'password': {'write_only': True}  # Ensure password is write-only
        }

    def create(self, validated_data):
        # Use set_password() to hash the password
        user = User(
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

# WhatsApp OTP Serializers
class WASendLinkOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()

class WAVerifyLinkSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

class WARegisterRequestSerializer(serializers.Serializer):
    phone = serializers.CharField()
    email = serializers.EmailField(required=False, allow_blank=True)

class WARegisterVerifySerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.CharField(max_length=6)

class WASendOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()

class WAVerifyOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.CharField(max_length=6)
