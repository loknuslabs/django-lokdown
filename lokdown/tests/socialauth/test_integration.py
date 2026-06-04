from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth.models import User
from django.test import Client, override_settings
from django.urls import reverse


@pytest.mark.django_db
class TestDummyProviderIntegration:
    """End-to-end flow using allauth's dummy provider (no external OAuth)."""

    @override_settings(SOCIALACCOUNT_LOGIN_ON_GET=True)
    def test_dummy_login_redirects_to_authenticate_with_state(self):
        client = Client()
        response = client.get(reverse("dummy_login"))
        assert response.status_code == 302
        assert "dummy/authenticate" in response.url
        assert parse_qs(urlparse(response.url).query).get("state")

    @override_settings(SOCIALACCOUNT_LOGIN_ON_GET=True)
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

    def test_allauth_account_login_url_resolves(self):
        client = Client()
        response = client.get(reverse("account_login"))
        assert response.status_code == 200

    def test_google_login_url_resolves(self):
        assert reverse("google_login") == "/accounts/google/login/"
