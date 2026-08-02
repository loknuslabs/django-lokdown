from rest_framework import serializers


class TOTPSetupRequestSerializer(serializers.Serializer):
    """Empty body — setup applies to the authenticated user."""


class TOTPSetupResponseSerializer(serializers.Serializer):
    secret = serializers.CharField()
    qr_code = serializers.CharField()
    provisioning_uri = serializers.CharField()


class TOTPVerifySetupRequestSerializer(serializers.Serializer):
    totp_token = serializers.CharField()


class MessageResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class TwoFactorSetupCompleteResponseSerializer(serializers.Serializer):
    """Returned after successful TOTP enrollment verification."""

    message = serializers.CharField()
    backup_codes = serializers.ListField(
        child=serializers.CharField(),
        help_text=("Plaintext backup codes shown once after TOTP setup. " "They are not returned again via the API."),
    )


class ErrorResponseSerializer(serializers.Serializer):
    error = serializers.CharField()
