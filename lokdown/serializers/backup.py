from rest_framework import serializers

from lokdown.serializers.auth import TokenPairResponseSerializer


class BackupCodeVerifyRequestSerializer(serializers.Serializer):
    session_id = serializers.CharField()
    backup_code = serializers.CharField()


class BackupCodeVerifyResponseSerializer(TokenPairResponseSerializer):
    message = serializers.CharField()
