import pytest
from django.core.checks import run_checks
from django.test import override_settings

from lokdown.checks import (
    ADMIN_2FA_FEATURES_CHECK_ID,
    ADMIN_2FA_REQUIRED_CHECK_ID,
    WEBAUTHN_ORIGINS_CHECK_ID,
    check_admin_2fa_features,
    check_admin_2fa_required,
    check_webauthn_origins,
)


@pytest.mark.django_db
class TestAdmin2faRequiredCheck:
    @override_settings(DEBUG=False, ADMIN_2FA_REQUIRED=True)
    def test_no_warning_when_explicitly_enabled(self):
        assert check_admin_2fa_required(None) == []

    @override_settings(DEBUG=False, ADMIN_2FA_REQUIRED=False)
    def test_no_warning_when_explicitly_disabled(self):
        assert check_admin_2fa_required(None) == []

    @override_settings(DEBUG=True)
    def test_no_warning_when_debug_true_and_setting_unset(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "ADMIN_2FA_REQUIRED", raising=False)
        assert check_admin_2fa_required(None) == []

    @override_settings(DEBUG=False)
    def test_warns_when_unset_in_production(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "ADMIN_2FA_REQUIRED", raising=False)
        warnings = check_admin_2fa_required(None)
        assert len(warnings) == 1
        assert warnings[0].id == ADMIN_2FA_REQUIRED_CHECK_ID

    @override_settings(DEBUG=False)
    def test_registered_with_run_checks(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "ADMIN_2FA_REQUIRED", raising=False)
        results = run_checks()
        assert any(result.id == ADMIN_2FA_REQUIRED_CHECK_ID for result in results)


@pytest.mark.django_db
class TestWebauthnOriginsCheck:
    @override_settings(DEBUG=False, WEBAUTHN_ORIGINS=["https://app.example.com"])
    def test_no_warning_when_origins_configured(self):
        assert check_webauthn_origins(None) == []

    @override_settings(DEBUG=True, WEBAUTHN_ORIGINS=[])
    def test_no_warning_when_debug_true_and_origins_unset(self):
        assert check_webauthn_origins(None) == []

    @override_settings(DEBUG=False, WEBAUTHN_ORIGINS=[], WEBAUTHN_ORIGIN="")
    def test_warns_when_unset_in_production(self):
        warnings = check_webauthn_origins(None)
        assert len(warnings) == 1
        assert warnings[0].id == WEBAUTHN_ORIGINS_CHECK_ID

    @override_settings(DEBUG=False, WEBAUTHN_ORIGINS=[], WEBAUTHN_ORIGIN="")
    def test_registered_with_run_checks(self):
        results = run_checks()
        assert any(result.id == WEBAUTHN_ORIGINS_CHECK_ID for result in results)


@pytest.mark.django_db
class TestAdmin2faFeaturesCheck:
    @override_settings(
        ADMIN_2FA_REQUIRED=True,
        LOKDOWN_TOTP_ENABLED=True,
        LOKDOWN_PASSKEY_ENABLED=False,
    )
    def test_no_warning_when_totp_enabled(self):
        assert check_admin_2fa_features(None) == []

    @override_settings(
        ADMIN_2FA_REQUIRED=True,
        LOKDOWN_TOTP_ENABLED=False,
        LOKDOWN_PASSKEY_ENABLED=True,
    )
    def test_no_warning_when_passkey_enabled(self):
        assert check_admin_2fa_features(None) == []

    @override_settings(
        ADMIN_2FA_REQUIRED=False,
        LOKDOWN_TOTP_ENABLED=False,
        LOKDOWN_PASSKEY_ENABLED=False,
    )
    def test_no_warning_when_admin_2fa_not_required(self):
        assert check_admin_2fa_features(None) == []

    @override_settings(
        ADMIN_2FA_REQUIRED=True,
        LOKDOWN_TOTP_ENABLED=False,
        LOKDOWN_PASSKEY_ENABLED=False,
    )
    def test_warns_when_no_enrollment_methods_enabled(self):
        warnings = check_admin_2fa_features(None)
        assert len(warnings) == 1
        assert warnings[0].id == ADMIN_2FA_FEATURES_CHECK_ID

    @override_settings(
        ADMIN_2FA_REQUIRED=True,
        LOKDOWN_TOTP_ENABLED=False,
        LOKDOWN_PASSKEY_ENABLED=False,
    )
    def test_registered_with_run_checks(self):
        results = run_checks()
        assert any(result.id == ADMIN_2FA_FEATURES_CHECK_ID for result in results)
