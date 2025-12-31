from rest_framework import serializers
from authentication.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from organization.models import OrganizationMember
from iam.models import Permission

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

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # 1. Find the Active Session
        try:
            member = OrganizationMember.objects.get(user=user, is_session_active=True)
            
            # 2. Add Organization ID
            token['org_id'] = str(member.organization.id)
            
            # 3. Add Roles
            # UserRole links OrganizationMember to Role
            roles = list(member.userrole_set.values_list('role__name', flat=True))
            token['roles'] = roles
            
            # 4. Add Permissions
            permissions = set()
            
            # 4a. Permissions from Roles
            role_permissions = Permission.objects.filter(roles__userrole__organization_member=member).values_list('name', flat=True)
            permissions.update(role_permissions)
            
            # 4b. Direct Permissions
            # UserPermission links OrganizationMember to Permission (via M2M permissions field)
            direct_permissions = Permission.objects.filter(direct_members__organization_member=member).values_list('name', flat=True)
            permissions.update(direct_permissions)
            
            token['permissions'] = list(permissions)
            
        except OrganizationMember.DoesNotExist:
            # Handle user with no active session (maybe new user or just created)
            token['org_id'] = None
            token['roles'] = []
            token['permissions'] = []

        return token

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

# Reverse WA OTP Serializers (n8n webhook method)
class WAReverseSendLinkOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()

class WAReverseRegisterRequestSerializer(serializers.Serializer):
    phone = serializers.CharField()
    email = serializers.EmailField(required=False, allow_blank=True)

class WAReverseSendOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()