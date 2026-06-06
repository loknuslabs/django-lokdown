import pytest
from django.test import override_settings

from lokdown.serializers.socialauth import OAuthProviderRedirectSerializer
from lokdown.socialauth.callback_url import (
    InvalidOAuthCallbackUrlError,
    is_safe_oauth_callback_url,
    resolve_oauth_callback_url,
)


@pytest.mark.django_db
class TestOAuthCallbackUrlValidation:
    def test_resolve_default_callback_uses_auth_callback(self, rf):
        request = rf.get("/api/auth/oauth/providers")
        resolved = resolve_oauth_callback_url(request)
        assert resolved.endswith("/auth/callback")

    def test_resolve_relative_callback(self, rf):
        request = rf.get("/api/auth/oauth/providers")
        resolved = resolve_oauth_callback_url(request, "/spa/oauth/callback")
        assert resolved.endswith("/spa/oauth/callback")

    @override_settings(LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS=["http://localhost:5173"])
    def test_allowed_spa_origin_passes(self, rf):
        request = rf.get("/api/auth/oauth/providers")
        url = "http://localhost:5173/oauth/callback"
        assert is_safe_oauth_callback_url(request, url) is True
        assert resolve_oauth_callback_url(request, url) == url

    @override_settings(LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS=["http://localhost:5173"])
    def test_disallowed_origin_rejected(self, rf):
        request = rf.get("/api/auth/oauth/providers")
        url = "https://evil.example/oauth/callback"
        assert is_safe_oauth_callback_url(request, url) is False
        with pytest.raises(InvalidOAuthCallbackUrlError):
            resolve_oauth_callback_url(request, url)

    def test_provider_redirect_serializer_for_provider(self, rf):
        request = rf.get("/api/auth/oauth/google/login")
        serializer = OAuthProviderRedirectSerializer.for_provider(
            request,
            "google",
            "http://localhost:5173/oauth/callback",
        )
        assert serializer.data["provider"] == "google"
        assert serializer.data["redirect_method"] == "POST"
        assert "/_allauth/browser/v1/auth/provider/redirect" in serializer.data["redirect_url"]

    @override_settings(LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS=["http://localhost:5173"])
    def test_provider_redirect_serializer_rejects_invalid_callback(self, rf):
        request = rf.get("/api/auth/oauth/google/login")
        with pytest.raises(InvalidOAuthCallbackUrlError):
            OAuthProviderRedirectSerializer.for_provider(
                request,
                "google",
                "https://evil.example/oauth/callback",
            )
