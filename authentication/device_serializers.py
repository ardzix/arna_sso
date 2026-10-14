from django.conf import settings
from rest_framework import serializers


class DeviceAuthorizeSerializer(serializers.Serializer):
    client_id = serializers.CharField(max_length=120)
    device_name = serializers.CharField(max_length=120)
    organization_id = serializers.UUIDField(required=False)
    tenant_id = serializers.UUIDField(required=False)
    audience = serializers.CharField(max_length=120)
    scopes = serializers.ListField(child=serializers.CharField(max_length=120), allow_empty=False, max_length=32)
    public_key_thumbprint = serializers.RegexField(r"^[A-Za-z0-9_-]{43}$", required=False, allow_blank=True)

    def validate(self, data):
        allowed = settings.DEVICE_AUDIENCE_SCOPES.get(data["audience"], [])
        if (data["audience"] not in settings.DEVICE_ALLOWED_AUDIENCES
                or not allowed or not set(data["scopes"]).issubset(allowed)):
            raise serializers.ValidationError({"scopes": "Audience/scopes are not permitted for this device resource."})
        data["scopes"] = sorted(set(data["scopes"]))
        return data


class DeviceReviewSerializer(serializers.Serializer):
    user_code = serializers.RegexField(r"^[A-HJ-NP-Z2-9]{4}-?[A-HJ-NP-Z2-9]{4}$")
    organization_id = serializers.UUIDField(required=False)

    def validate_user_code(self, value):
        return value.replace("-", "").upper()

    def to_internal_value(self, data):
        if isinstance(data, dict) and isinstance(data.get("user_code"), str):
            data = {**data, "user_code": data["user_code"].strip().upper()}
        return super().to_internal_value(data)


class DeviceDecisionSerializer(DeviceReviewSerializer):
    action = serializers.ChoiceField(choices=["approve", "deny"])


class DeviceTokenSerializer(serializers.Serializer):
    grant_type = serializers.CharField(max_length=100)
    device_code = serializers.CharField(max_length=128, trim_whitespace=False)


class DeviceRefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=128, trim_whitespace=False)


class DeviceRevokeSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()


class DeviceInventorySerializer(serializers.Serializer):
    organization_id = serializers.UUIDField(required=False)
    tenant_id = serializers.UUIDField(required=False)
    page = serializers.IntegerField(min_value=1, default=1)
    page_size = serializers.IntegerField(min_value=1, max_value=100, default=20)


class DeviceIntrospectionSerializer(serializers.Serializer):
    access_token = serializers.CharField(max_length=8192, trim_whitespace=False, write_only=True)
    audience = serializers.CharField(max_length=120)


class DeviceRegistrationResponseSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    client_id = serializers.CharField()
    device_name = serializers.CharField()
    organization_id = serializers.UUIDField()
    tenant_id = serializers.UUIDField()
    audience = serializers.CharField()
    scopes = serializers.ListField(child=serializers.CharField())
    is_active = serializers.BooleanField()
    credential_version = serializers.IntegerField()
    key_bound = serializers.BooleanField()
    approved_at = serializers.DateTimeField(allow_null=True)
    last_seen_at = serializers.DateTimeField(allow_null=True)


class DeviceInventoryResponseSerializer(serializers.Serializer):
    count = serializers.IntegerField()
    page = serializers.IntegerField()
    page_size = serializers.IntegerField()
    results = DeviceRegistrationResponseSerializer(many=True)


class DeviceReviewResponseSerializer(serializers.Serializer):
    client_id = serializers.CharField()
    device_name = serializers.CharField()
    organization_id = serializers.UUIDField()
    organization_name = serializers.CharField()
    tenant_id = serializers.UUIDField()
    audience = serializers.CharField()
    scopes = serializers.ListField(child=serializers.CharField())
    key_bound = serializers.BooleanField()
    expires_at = serializers.DateTimeField()


class DeviceErrorSerializer(serializers.Serializer):
    error = serializers.CharField()
    detail = serializers.CharField()
    request_id = serializers.UUIDField()
    fields = serializers.JSONField(required=False, allow_null=True)
    interval = serializers.IntegerField(required=False)


class DeviceStatusResponseSerializer(DeviceRegistrationResponseSerializer):
    active = serializers.BooleanField()


class DeviceContextSerializer(serializers.Serializer):
    tenant_id = serializers.UUIDField()


class DeviceAccessSerializer(serializers.Serializer):
    role_ids = serializers.ListField(child=serializers.UUIDField(), max_length=100)
    permission_ids = serializers.ListField(child=serializers.UUIDField(), max_length=100)


class ResourceTokenSerializer(serializers.Serializer):
    audience = serializers.ChoiceField(choices=['storage', 'arna-commerce'])
