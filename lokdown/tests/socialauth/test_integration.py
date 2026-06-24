from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth.models import User
from django.test import Client, override_settings
from django.urls import reverse


@pytest.mark.django_db
class TestDummyProviderIntegration:
    """End-to-end flow using allauth's dummy provider (no external OAuth)."""

    @override_settings(SOCIALACCOUNT_LOGIN_ON_GET=True, HEADLESS_ONLY=False)
    def test_dummy_login_redirects_to_authenticate_with_state(self):
        client = Client()
        response = client.get(reverse("dummy_login"))
        assert response.status_code == 302
        assert "dummy/authenticate" in response.url
        assert parse_qs(urlparse(response.url).query).get("state")

    @override_settings(SOCIALACCOUNT_LOGIN_ON_GET=True, HEADLESS_ONLY=False, LOKDOWN_ALLOW_PUBLIC_REGISTRATION=True)
    def test_dummy_signup_creates_user_with_email_username(self):
        client = Client()
        login_response = client.get(reverse("dummy_login"))
        state = parse_qs(urlparse(login_response.url).query)["state"][0]
        auth_url = f"{reverse('dummy_authenticate')}?state={state}"
        response = client.post(
            auth_url,
            data={
                "id": 42,
                "email": "oauth.user@example.com",
                "email_verified": "on",
            },
        )
        assert response.status_code == 302
        user = User.objects.get(email="oauth.user@example.com")
        assert user.username == "oauth.user@example.com"

    @override_settings(SOCIALACCOUNT_LOGIN_ON_GET=True, HEADLESS_ONLY=False, LOKDOWN_ALLOW_PUBLIC_REGISTRATION=False)
    def test_dummy_signup_blocked_when_public_registration_disabled(self):
        client = Client()
        login_response = client.get(reverse("dummy_login"))
        state = parse_qs(urlparse(login_response.url).query)["state"][0]
        auth_url = f"{reverse('dummy_authenticate')}?state={state}"
        response = client.post(
            auth_url,
            data={
                "id": 99,
                "email": "blocked.user@example.com",
                "email_verified": "on",
            },
        )
        assert response.status_code in (302, 403, 200)
        assert not User.objects.filter(email="blocked.user@example.com").exists()

    def test_google_login_url_resolves(self):
        assert reverse("google_login") == "/accounts/google/login/"

    def test_headless_config_lists_providers(self):
        client = Client()
        response = client.get("/_allauth/browser/v1/config")
        assert response.status_code == 200
        payload = response.json()
        provider_ids = {p["id"] for p in payload["data"]["socialaccount"]["providers"]}
        assert "google" in provider_ids
        assert "dummy" in provider_ids
