from rest_framework import serializers
from .models import UserTimeBasedOneTimePasswords, PasskeyCredential, LoginSession, BackupCodes


class LoginInitSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()


class LoginVerifySerializer(serializers.Serializer):
    session_id = serializers.CharField()
    totp_token = serializers.CharField(required=False, allow_blank=True)
    passkey_response = serializers.JSONField(required=False)
    backup_code = serializers.CharField(required=False, allow_blank=True)


class TOTPSetupSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()


class TOTPVerifySerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    totp_token = serializers.CharField()
    secret = serializers.CharField(required=False)


class PasskeySetupSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()


class PasskeyVerifySerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    passkey_response = serializers.JSONField()


class TwoFactorAuthSerializer(serializers.ModelSerializer):
    is_enabled = serializers.SerializerMethodField()
    totp_enabled = serializers.SerializerMethodField()
    passkey_enabled = serializers.SerializerMethodField()

    class Meta:
        model = UserTimeBasedOneTimePasswords
        fields = ['is_enabled', 'totp_enabled', 'passkey_enabled']

    def get_is_enabled(self, obj):
        """Check if 2FA is enabled (either TOTP or Passkey)"""
        has_totp = bool(obj.totp_secret)
        has_passkey = obj.user.passkey_credentials.exists()
        return has_totp or has_passkey

    def get_totp_enabled(self, obj):
        """Check if TOTP is enabled"""
        return bool(obj.totp_secret)

    def get_passkey_enabled(self, obj):
        """Check if Passkey is enabled"""
        return obj.user.passkey_credentials.exists()


class BackupCodeSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    backup_code = serializers.CharField()


class PasskeyCredentialSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasskeyCredential
        fields = [
            'id',
            'credential_id',
            'sign_count',
            'rp_id',
            'user_handle',
            'created_at',
            'last_used',
        ]


class LoginSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginSession
        fields = [
            'session_id',
            'is_authenticated',
            'requires_2fa',
            'totp_verified',
            'passkey_verified',
            'created_at',
            'expires_at',
        ]


class BackupCodesSerializer(serializers.ModelSerializer):
    class Meta:
        model = BackupCodes
        fields = [
            'id',
            'codes',
            'created_at',
            'updated_at',
        ]
