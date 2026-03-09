import re
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Organization, OrganizationMember

User = get_user_model()

# UUID v4 pattern (8-4-4-4-12 hex)
UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


class UserLookupField(serializers.Field):
    """
    Field that accepts user identifier in various formats:
    - UUID: user id
    - Email: user email address
    - Phone: user phone number
    """
    default_error_messages = {
        'not_found': 'User not found with identifier: {value}',
        'invalid': 'Invalid identifier format.',
    }

    def to_internal_value(self, data):
        if not data or not isinstance(data, str):
            raise serializers.ValidationError(self.default_error_messages['invalid'])
        
        value = str(data).strip()
        if not value:
            raise serializers.ValidationError(self.default_error_messages['invalid'])

        user = None
        
        # 1. Check UUID format
        if UUID_PATTERN.match(value):
            try:
                user = User.objects.get(id=value)
            except User.DoesNotExist:
                pass
        
        # 2. Check email (contains @)
        if user is None and '@' in value:
            try:
                user = User.objects.get(email__iexact=value)
            except User.DoesNotExist:
                pass
        
        # 3. Check phone number (digits only, normalize 62/0)
        if user is None:
            phone_clean = re.sub(r'[\s\-\(\)\+]', '', value)
            if phone_clean and phone_clean.isdigit():
                # Try original format, 08xxx, and 628xxx
                variants = [phone_clean]
                if phone_clean.startswith('62') and len(phone_clean) >= 10:
                    variants.append('0' + phone_clean[2:])
                elif phone_clean.startswith('0') and len(phone_clean) >= 10:
                    variants.append('62' + phone_clean[1:])
                for p in variants:
                    user = User.objects.filter(
                        phone_number__isnull=False,
                        phone_number=p
                    ).first()
                    if user:
                        break

        if user is None:
            raise serializers.ValidationError(
                self.default_error_messages['not_found'].format(value=value)
            )
        
        return user

    def to_representation(self, value):
        if hasattr(value, 'id'):
            return str(value.id)
        return str(value)


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['id', 'name', 'owner', 'package_type', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'owner'] # Owner removed from Read Only

class SetCurrentOrganizationSerializer(serializers.Serializer):
    """Serializer for POST /api/organizations/current/"""
    organization_id = serializers.UUIDField(required=True, help_text="UUID of the organization to set as current")

class OrganizationMemberSerializer(serializers.ModelSerializer):
    user = UserLookupField(help_text='User ID (UUID), email, or phone number')
    user_name = serializers.ReadOnlyField(source='user.email')
    organization_name = serializers.ReadOnlyField(source='organization.name')

    class Meta:
        model = OrganizationMember
        fields = ['id', 'user', 'user_name', 'organization', 'organization_name', 'joined_at', 'is_session_active']
        read_only_fields = ['id', 'joined_at', 'is_session_active']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            self.fields['organization'].queryset = Organization.objects.filter(
                members__user=request.user,
                members__is_session_active=True
            ).distinct()

