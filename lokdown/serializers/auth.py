from rest_framework import serializers


class LoginInitRequestSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={"input_type": "password"}, write_only=True)


class LoginVerifyRequestSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    totp_token = serializers.CharField(required=False, allow_blank=True)
    passkey_response = serializers.JSONField(required=False)
    backup_code = serializers.CharField(required=False, allow_blank=True)


class Pre2FALoginResponseSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    requires_2fa = serializers.BooleanField()
    totp_enabled = serializers.BooleanField()
    passkey_enabled = serializers.BooleanField()
    backup_codes_available = serializers.BooleanField()


class TokenPairResponseSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    requires_2fa = serializers.BooleanField()


class SimpleJwtTokenPairResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField()
    requires_2fa = serializers.BooleanField()


class TokenVerify2FARequestSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    totp_token = serializers.CharField(required=False, allow_blank=True)
    passkey_response = serializers.JSONField(required=False)
    backup_code = serializers.CharField(required=False, allow_blank=True)


class DisableTwoFAResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class AdminPasskeyAuthOptionsResponseSerializer(serializers.Serializer):
    challenge = serializers.CharField()
    rp_id = serializers.CharField()
    timeout = serializers.IntegerField()
    allow_credentials = serializers.JSONField(required=False)
