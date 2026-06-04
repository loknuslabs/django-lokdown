import pytest
from django.test import Client, override_settings
from django.urls import reverse


@pytest.fixture
def middleware_client():
    return Client()


@pytest.mark.django_db
class TestRedirectAuthenticatedSocialLoginMiddleware:
    def test_authenticated_google_login_redirects_to_next(self, middleware_client, user):
        middleware_client.force_login(user)
        response = middleware_client.get(
            "/accounts/google/login/",
            {"next": "/spa/dashboard"},
        )
        assert response.status_code == 302
        assert response["Location"] == "/spa/dashboard"

    def test_authenticated_google_login_redirects_to_callback_without_next(self, middleware_client, user):
        middleware_client.force_login(user)
        response = middleware_client.get("/accounts/google/login/")
        assert response.status_code == 302
        assert response.url == reverse("auth_callback")

    def test_connect_process_not_short_circuited(self, middleware_client, user):
        middleware_client.force_login(user)
        response = middleware_client.get(
            "/accounts/google/login/",
            {"process": "connect"},
        )
        assert response.status_code != 302 or "google" in response.url

    def test_unauthenticated_passes_through(self, middleware_client):
        response = middleware_client.get("/accounts/google/login/")
        assert response.status_code in (200, 302)
        if response.status_code == 302:
            assert "google" in response.url.lower() or "oauth" in response.url.lower()

    @override_settings(LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS=["dummy"])
    def test_authenticated_dummy_login_redirects(self, middleware_client, user):
        middleware_client.force_login(user)
        response = middleware_client.get("/accounts/dummy/login/", {"next": "/done"})
        assert response.status_code == 302
        assert response["Location"] == "/done"


@pytest.mark.django_db
class TestAutoRedirectAccountLoginToSocialMiddleware:
    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER="google")
    def test_account_login_redirects_to_google(self, middleware_client):
        response = middleware_client.get("/accounts/login/", {"next": "/auth/callback"})
        assert response.status_code == 302
        assert reverse("google_login") in response.url
        assert "next=" in response.url

    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_GOOGLE=True)
    def test_legacy_google_flag_redirects(self, middleware_client):
        response = middleware_client.get("/accounts/login/")
        assert response.status_code == 302
        assert reverse("google_login") in response.url

    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER="google")
    def test_local_opt_out_shows_login_page(self, middleware_client):
        response = middleware_client.get("/accounts/login/", {"local": "1"})
        assert response.status_code == 200

    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER="google")
    def test_authenticated_user_not_redirected_to_google_from_login(self, middleware_client, user):
        middleware_client.force_login(user)
        response = middleware_client.get("/accounts/login/")
        assert response.status_code == 302
        assert reverse("google_login") not in response.url

    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER="google")
    def test_password_query_opt_out(self, middleware_client):
        response = middleware_client.get("/accounts/login/", {"password": "1"})
        assert response.status_code == 200

    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER="google")
    def test_email_query_opt_out(self, middleware_client):
        response = middleware_client.get("/accounts/login/", {"email": "a@b.com"})
        assert response.status_code == 200

    @override_settings(
        SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER="google",
        LOKDOWN_SOCIALAUTH_ACCOUNT_URL_PREFIX="sso",
    )
    def test_custom_account_prefix_for_auto_redirect(self, middleware_client):
        response = middleware_client.get("/sso/login/")
        assert response.status_code == 302
        assert reverse("google_login") in response.url

    def test_auto_redirect_disabled(self, middleware_client):
        response = middleware_client.get("/accounts/login/")
        assert response.status_code == 200
