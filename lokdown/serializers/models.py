from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from lokdown.models import (
    UserTimeBasedOneTimePasswords,
    LoginSession,
    BackupCodes,
)


class TwoFactorStatusResponseSerializer(serializers.ModelSerializer):
    is_enabled = serializers.SerializerMethodField()
    totp_enabled = serializers.SerializerMethodField()
    passkey_enabled = serializers.SerializerMethodField()

    class Meta:
        model = UserTimeBasedOneTimePasswords
        fields = ["is_enabled", "totp_enabled", "passkey_enabled"]

    @extend_schema_field(serializers.BooleanField)
    def get_is_enabled(self, obj):
        has_totp = bool(obj.totp_secret)
        has_passkey = obj.user.passkey_credentials.exists()
        return has_totp or has_passkey

    @extend_schema_field(serializers.BooleanField)
    def get_totp_enabled(self, obj):
        return bool(obj.totp_secret)

    @extend_schema_field(serializers.BooleanField)
    def get_passkey_enabled(self, obj):
        return obj.user.passkey_credentials.exists()


class LoginSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginSession
        fields = [
            "session_id",
            "is_authenticated",
            "requires_2fa",
            "totp_verified",
            "passkey_verified",
            "created_at",
            "expires_at",
        ]


class BackupCodesSerializer(serializers.ModelSerializer):
    remaining_count = serializers.SerializerMethodField()

    class Meta:
        model = BackupCodes
        fields = ["id", "remaining_count", "created_at", "updated_at"]

    @extend_schema_field(serializers.IntegerField)
    def get_remaining_count(self, obj):
        return len(obj.codes or [])
