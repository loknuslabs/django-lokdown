from lokdown.socialauth.providers import (
    CUSTOM_LOGIN_URL_NAMES,
    CUSTOM_PROVIDER_SLUGS,
    SOCIALAUTH_PROVIDER_APPS,
)


class TestProviderRegistry:
    def test_common_providers_registered(self):
        for provider_id in ("google", "github", "microsoft", "facebook", "dummy"):
            assert provider_id in SOCIALAUTH_PROVIDER_APPS

    def test_custom_login_url_names(self):
        assert CUSTOM_LOGIN_URL_NAMES["dummy"] == "dummy_login"
        assert CUSTOM_LOGIN_URL_NAMES["steam"] == "steam_login"

    def test_custom_provider_slugs(self):
        assert CUSTOM_PROVIDER_SLUGS["linkedin_oauth2"] == "linkedin"

    def test_google_app_path(self):
        assert SOCIALAUTH_PROVIDER_APPS["google"] == "allauth.socialaccount.providers.google"
