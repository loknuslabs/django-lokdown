from rest_framework import serializers

from lokdown.socialauth.callback_url import build_oauth_redirect_metadata


class OAuthProviderRedirectSerializer(serializers.Serializer):
    """
    Headless OAuth start metadata for one provider.

    Use :meth:`for_provider` to build a validated instance from the current request.
    """

    provider = serializers.CharField(help_text="Provider id (e.g. google, github)")
    redirect_url = serializers.URLField(
        help_text="POST target for allauth headless browser provider redirect",
    )
    callback_url = serializers.URLField(
        help_text=(
            "SPA route allauth redirects to after OAuth completes. Must pass allauth "
            "`is_safe_url` and, when set, ``LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS``."
        ),
    )
    redirect_method = serializers.CharField(
        help_text='HTTP method for redirect_url (always "POST" for headless browser flow)',
    )

    @classmethod
    def for_provider(
        cls,
        request,
        provider_id: str,
        callback_url: str | None = None,
    ) -> "OAuthProviderRedirectSerializer":
        """
        Build validated redirect metadata for OpenAPI-documented responses.

        URL safety is enforced in ``build_oauth_redirect_metadata``; this serializer
        shapes the response for schema generation and consistent API output.
        """
        data = build_oauth_redirect_metadata(request, provider_id, callback_url)
        return cls(instance=data)


class OAuthProvidersResponseSerializer(serializers.Serializer):
    providers = OAuthProviderRedirectSerializer(many=True)


# Backwards-compatible OpenAPI / import aliases
OAuthProviderEntrySerializer = OAuthProviderRedirectSerializer
OAuthLoginUrlResponseSerializer = OAuthProviderRedirectSerializer


class OAuthSessionBridgeRequestSerializer(serializers.Serializer):
    """Empty request body; authenticates via Django session cookie and CSRF."""


class OAuthSessionBridgeResponseSerializer(serializers.Serializer):
    """JWT pair or pre-2FA session after OAuth (same shape as password login)."""

    requires_2fa = serializers.BooleanField()
    access_token = serializers.CharField(required=False)
    refresh_token = serializers.CharField(required=False)
    session_id = serializers.CharField(required=False)
    totp_enabled = serializers.BooleanField(required=False)
    passkey_enabled = serializers.BooleanField(required=False)
    backup_codes_available = serializers.BooleanField(required=False)
