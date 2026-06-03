from rest_framework import serializers


class TOTPSetupRequestSerializer(serializers.Serializer):
    """Empty body — setup applies to the authenticated user."""


class TOTPSetupResponseSerializer(serializers.Serializer):
    secret = serializers.CharField()
    qr_code = serializers.CharField()
    provisioning_uri = serializers.CharField()


class TOTPVerifySetupRequestSerializer(serializers.Serializer):
    totp_token = serializers.CharField()
    secret = serializers.CharField()


class MessageResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class ErrorResponseSerializer(serializers.Serializer):
    error = serializers.CharField()
