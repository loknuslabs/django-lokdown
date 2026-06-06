from django.test import override_settings

from lokdown.helpers.api_key_settings_helper import (
    api_key_max_lifespan_days,
    api_keys_allow_indefinite,
    api_keys_enabled,
    max_allowed_expires_at,
)


class TestApiKeySettingsHelper:
    @override_settings(
        LOKDOWN_API_KEYS_ENABLED=False,
        LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS=None,
    )
    def test_defaults(self):
        assert api_keys_enabled() is False
        assert api_keys_allow_indefinite() is True
        assert api_key_max_lifespan_days() is None
        assert max_allowed_expires_at() is None

    @override_settings(
        LOKDOWN_API_KEYS_ENABLED=True,
        LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS=90,
        LOKDOWN_API_KEY_ALLOW_INDEFINITE=False,
    )
    def test_configured_values(self):
        assert api_keys_enabled() is True
        assert api_keys_allow_indefinite() is False
        assert api_key_max_lifespan_days() == 90
        assert max_allowed_expires_at() is not None
