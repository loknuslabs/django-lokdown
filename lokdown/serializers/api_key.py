from rest_framework import serializers


class ApiKeyCreateRequestSerializer(serializers.Serializer):
    name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    expires_in_days = serializers.IntegerField(
        required=False,
        min_value=1,
        help_text="Days until expiry. Omit for indefinite when allowed by settings.",
    )


class ApiKeyCreatedResponseSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    prefix = serializers.CharField(help_text="Visible key prefix for identification")
    api_key = serializers.CharField(help_text="Full key — shown once at creation")
    created_at = serializers.DateTimeField()
    expires_at = serializers.DateTimeField(allow_null=True)


class ApiKeyMetadataSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    prefix = serializers.CharField()
    created_at = serializers.DateTimeField()
    last_used_at = serializers.DateTimeField(allow_null=True)
    expires_at = serializers.DateTimeField(allow_null=True)
    is_active = serializers.BooleanField()


class ApiKeyListResponseSerializer(serializers.Serializer):
    api_keys = ApiKeyMetadataSerializer(many=True)


class ApiKeyRevokeResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
