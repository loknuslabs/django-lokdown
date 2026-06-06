import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.fixture
def oauth_api_client():
    return APIClient()


@pytest.mark.django_db
class TestOAuthApiEndpoints:
    def test_oauth_providers_lists_configured_providers(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_providers"))
        assert response.status_code == 200
        ids = {p["provider"] for p in response.data["providers"]}
        assert "google" in ids
        assert "dummy" in ids
        assert all(p["redirect_url"].startswith("http") for p in response.data["providers"])
        assert all(p["redirect_method"] == "POST" for p in response.data["providers"])

    def test_oauth_providers_respects_callback_url_query(self, oauth_api_client):
        response = oauth_api_client.get(
            reverse("lokdown:oauth_providers"),
            {"callback_url": "http://localhost:5173/custom/callback"},
        )
        assert response.status_code == 200
        assert response.data["providers"][0]["callback_url"] == "http://localhost:5173/custom/callback"

    def test_oauth_providers_accepts_legacy_next_query(self, oauth_api_client):
        response = oauth_api_client.get(
            reverse("lokdown:oauth_providers"),
            {"next": "/custom/callback"},
        )
        assert response.status_code == 200
        assert response.data["providers"][0]["callback_url"].endswith("/custom/callback")

    @override_settings(LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS=["http://localhost:5173"])
    def test_oauth_providers_rejects_disallowed_callback_url(self, oauth_api_client):
        response = oauth_api_client.get(
            reverse("lokdown:oauth_providers"),
            {"callback_url": "https://evil.example/callback"},
        )
        assert response.status_code == 400
        assert "callback_url" in response.data

    def test_oauth_provider_login_google(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_provider_login", kwargs={"provider": "google"}))
        assert response.status_code == 200
        assert response.data["provider"] == "google"
        assert "/_allauth/browser/v1/auth/provider/redirect" in response.data["redirect_url"]
        assert response.data["redirect_method"] == "POST"

    def test_oauth_provider_login_unknown_returns_404(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_provider_login", kwargs={"provider": "notreal"}))
        assert response.status_code == 404

    def test_oauth_callback_bridge_requires_auth(self, oauth_api_client):
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code in (401, 403)

    def test_oauth_callback_bridge_rejects_get(self, oauth_api_client, user):
        oauth_api_client.force_login(user)
        response = oauth_api_client.get(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code == 405

    def test_oauth_callback_bridge_accepts_django_session_cookie(self, oauth_api_client, user):
        oauth_api_client.force_login(user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code == 200
        assert response.data["requires_2fa"] is False
        assert "access_token" in response.data

    def test_oauth_callback_bridge_returns_jwt_without_2fa(self, oauth_api_client, user):
        oauth_api_client.force_authenticate(user=user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code == 200
        assert response.data["requires_2fa"] is False
        assert "access_token" in response.data
        assert "refresh_token" in response.data

    def test_oauth_callback_bridge_returns_session_with_2fa(self, oauth_api_client, user_with_totp):
        oauth_api_client.force_authenticate(user=user_with_totp)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code == 200
        assert response.data["requires_2fa"] is True
        assert response.data["session_id"]
        assert response.data["totp_enabled"] is True

    @override_settings(INSTALLED_APPS=["django.contrib.auth", "rest_framework", "lokdown"])
    def test_oauth_providers_503_without_allauth(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_providers"))
        assert response.status_code == 503
