from rest_framework import serializers
from .models import Organization, OrganizationMember

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['id', 'name', 'owner', 'package_type', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'owner'] # Owner removed from Read Only

class OrganizationMemberSerializer(serializers.ModelSerializer):
    user_name = serializers.ReadOnlyField(source='user.email')
    organization_name = serializers.ReadOnlyField(source='organization.name')

    class Meta:
        model = OrganizationMember
        fields = ['id', 'user', 'user_name', 'organization', 'organization_name', 'joined_at', 'is_session_active']
        read_only_fields = ['id', 'joined_at', 'is_session_active'] # is_session_active managed via switch-session action usually, but good to see it.

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Limit the organization selection if it's being displayed (e.g. for selection)
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            # Only allow creating members for organizations where current user has access
            # For simplicity, filtering to where they are member and active
             self.fields['organization'].queryset = Organization.objects.filter(
                 members__user=request.user,
                 members__is_session_active=True
             ).distinct()

