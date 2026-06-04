from rest_framework import serializers


class OAuthProviderEntrySerializer(serializers.Serializer):
    id = serializers.CharField(help_text="Provider id (e.g. google, github)")
    login_url = serializers.URLField(help_text="Absolute URL to start browser OAuth")


class OAuthProvidersResponseSerializer(serializers.Serializer):
    providers = OAuthProviderEntrySerializer(many=True)


class OAuthLoginUrlResponseSerializer(serializers.Serializer):
    provider = serializers.CharField()
    login_url = serializers.URLField(
        help_text="Redirect the user's browser to this URL to start OAuth"
    )
    next = serializers.CharField(
        required=False,
        allow_null=True,
        help_text="Post-OAuth redirect path passed to allauth (e.g. /auth/callback)",
    )


class OAuthSessionBridgeResponseSerializer(serializers.Serializer):
    """JWT pair or pre-2FA session after OAuth (same shape as password login)."""

    requires_2fa = serializers.BooleanField()
    access_token = serializers.CharField(required=False)
    refresh_token = serializers.CharField(required=False)
    session_id = serializers.CharField(required=False)
    totp_enabled = serializers.BooleanField(required=False)
    passkey_enabled = serializers.BooleanField(required=False)
    backup_codes_available = serializers.BooleanField(required=False)
