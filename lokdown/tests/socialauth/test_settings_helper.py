from django.test import override_settings

from lokdown.socialauth.settings_helper import (
    LOKDOWN_ALLAUTH_BASE_APPS,
    get_allauth_recommended_settings,
    get_auto_redirect_provider,
    get_enabled_social_providers,
    get_lokdown_socialauth_middleware,
    get_provider_installed_apps,
    get_social_login_url_name,
    social_login_path_prefix,
)


class TestSettingsHelper:
    def test_base_apps_include_sites_and_allauth(self):
        assert "django.contrib.sites" in LOKDOWN_ALLAUTH_BASE_APPS
        assert "allauth.socialaccount" in LOKDOWN_ALLAUTH_BASE_APPS

    def test_get_enabled_social_providers_from_apps_config(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        with override_settings(
            SOCIALACCOUNT_PROVIDERS={
                "google": {"APPS": [{"client_id": "a", "secret": "b"}]},
                "github": {"VERIFIED_EMAIL": True},
            }
        ):
            assert get_enabled_social_providers() == ["google"]

    @override_settings(LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS=["dummy", "google"])
    def test_explicit_enabled_providers_override(self):
        assert get_enabled_social_providers() == ["dummy", "google"]

    def test_get_provider_installed_apps(self):
        apps = get_provider_installed_apps(["google", "dummy"])
        assert "allauth.socialaccount.providers.google" in apps
        assert "allauth.socialaccount.providers.dummy" in apps

    def test_get_social_login_url_name_oauth2_and_custom(self):
        assert get_social_login_url_name("google") == "google_login"
        assert get_social_login_url_name("dummy") == "dummy_login"

    @override_settings(LOKDOWN_SOCIALAUTH_ACCOUNT_URL_PREFIX="accounts")
    def test_social_login_path_prefix(self):
        assert social_login_path_prefix("google") == "/accounts/google/login"
        assert social_login_path_prefix("linkedin_oauth2") == "/accounts/linkedin/login"

    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER="github")
    def test_auto_redirect_provider_explicit(self):
        assert get_auto_redirect_provider() == "github"

    @override_settings(SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_GOOGLE=True)
    def test_auto_redirect_provider_legacy_google_flag(self):
        assert get_auto_redirect_provider() == "google"

    def test_recommended_settings_include_adapter(self):
        cfg = get_allauth_recommended_settings()
        assert cfg["SOCIALACCOUNT_ADAPTER"] == "lokdown.socialauth.adapters.CustomSocialAccountAdapter"
        assert "allauth.account.auth_backends.AuthenticationBackend" in cfg["AUTHENTICATION_BACKENDS"]

    def test_middleware_paths(self):
        paths = get_lokdown_socialauth_middleware()
        assert "AccountMiddleware" in paths[0]
        assert "RedirectAuthenticatedSocialLoginMiddleware" in paths[1]
        assert "AutoRedirectAccountLoginToSocialMiddleware" in paths[2]
