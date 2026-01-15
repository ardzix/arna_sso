from rest_framework import serializers
from authentication.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from organization.models import OrganizationMember
from iam.models import Permission

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'password']  # Ensure both email and password are included
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

        try:
            # Optimize query dengan select_related dan prefetch_related untuk avoid N+1 queries
            member = OrganizationMember.objects.select_related(
                'organization', 'organization__owner'
            ).prefetch_related(
                'userrole_set__role',
                'userrole_set__role__permissions',
                'userpermission_set__permissions'
            ).filter(
                user=user, 
                is_session_active=True
            ).first()
            
            if member and member.organization:
                token['org_id'] = str(member.organization.id)
                token['org_name'] = member.organization.name
                token['mfa_enabled'] = bool(user.mfa_secret)
                
                # Get roles (already prefetched)
                try:
                    roles = [ur.role.name for ur in member.userrole_set.all()]
                except Exception:
                    roles = []
                token['roles'] = roles
                
                # Get permissions (already prefetched)
                permissions = set()
                try:
                    # Permissions from roles
                    for ur in member.userrole_set.all():
                        for perm in ur.role.permissions.all():
                            permissions.add(perm.name)
                    
                    # Direct permissions
                    for up in member.userpermission_set.all():
                        for perm in up.permissions.all():
                            permissions.add(perm.name)
                except Exception:
                    permissions = set()
                
                token['permissions'] = list(permissions)
                token['is_owner'] = (member.organization.owner_id == user.id)
            else:
                # Handle user with no active session (maybe new user or just created)
                token['org_id'] = None
                token['roles'] = []
                token['permissions'] = []
                token['is_owner'] = False
                token['mfa_enabled'] = bool(user.mfa_secret)
        except Exception as e:
            # Log error but don't fail token generation
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error generating token claims for user {user.id}: {str(e)}", exc_info=True)
            
            # Return token with empty org context
            token['org_id'] = None
            token['roles'] = []
            token['permissions'] = []
            token['is_owner'] = False
            token['mfa_enabled'] = bool(user.mfa_secret)

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

class PreAuthTokenSerializer(serializers.Serializer):
    """
    Serializer to generate a short-lived Pre-Auth Token.
    This token proves the user has passed the first factor (password/social/otp)
    and is now eligible to attempt MFA verification.
    """
    @classmethod
    def get_token(cls, user):
        token = RefreshToken.for_user(user)
        # Customize the token
        token["type"] = "pre_auth"
        del token["token_type"] # Remove access/refresh type
        
        # Set short expiration from settings
        from django.conf import settings
        token.set_exp(lifetime=settings.SIMPLE_JWT['PRE_AUTH_TOKEN_LIFETIME'])
        
        return str(token)