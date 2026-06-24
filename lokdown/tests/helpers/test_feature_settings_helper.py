from django.test import override_settings

from lokdown.helpers.feature_settings_helper import (
    any_2fa_enrollment_enabled,
    feature_disabled_message,
    passkey_enabled,
    public_registration_enabled,
    socialauth_enabled,
    totp_enabled,
)


class TestFeatureSettingsHelper:
    @override_settings(
        LOKDOWN_PASSKEY_ENABLED=False,
        LOKDOWN_TOTP_ENABLED=False,
        LOKDOWN_SOCIALAUTH_ENABLED=False,
    )
    def test_defaults_disabled(self):
        assert passkey_enabled() is False
        assert totp_enabled() is False
        assert socialauth_enabled() is False
        assert public_registration_enabled() is False
        assert any_2fa_enrollment_enabled() is False

    @override_settings(
        LOKDOWN_PASSKEY_ENABLED=True,
        LOKDOWN_TOTP_ENABLED=False,
        LOKDOWN_SOCIALAUTH_ENABLED=True,
    )
    def test_individual_flags(self):
        assert passkey_enabled() is True
        assert totp_enabled() is False
        assert socialauth_enabled() is True
        assert any_2fa_enrollment_enabled() is True

    @override_settings(LOKDOWN_TOTP_ENABLED=True)
    def test_totp_enrollment_only(self):
        assert any_2fa_enrollment_enabled() is True

    @override_settings(LOKDOWN_ALLOW_PUBLIC_REGISTRATION=True)
    def test_public_registration_enabled(self):
        assert public_registration_enabled() is True

    def test_feature_disabled_message(self):
        assert feature_disabled_message("TOTP") == "TOTP support is disabled"
