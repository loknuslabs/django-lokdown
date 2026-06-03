from rest_framework import serializers

from lokdown.models import PasskeyCredential


class PasskeySetupRequestSerializer(serializers.Serializer):
    """Empty body — setup applies to the authenticated user."""


class PasskeySetupResponseSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    options = serializers.JSONField()


class PasskeyVerifySetupRequestSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    passkey_response = serializers.JSONField()


class PasskeyAuthOptionsRequestSerializer(serializers.Serializer):
    session_id = serializers.CharField()


class PasskeyAuthOptionsResponseSerializer(serializers.Serializer):
    challenge = serializers.CharField()
    rp_id = serializers.CharField()
    timeout = serializers.IntegerField()
    options = serializers.JSONField()


class PasskeyCredentialSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasskeyCredential
        fields = [
            "id",
            "credential_id",
            "sign_count",
            "rp_id",
            "user_handle",
            "created_at",
            "last_used",
        ]


class PasskeyRemoveQuerySerializer(serializers.Serializer):
    credential_id = serializers.CharField()
