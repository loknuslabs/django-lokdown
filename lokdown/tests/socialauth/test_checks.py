import pytest
from django.core.checks import run_checks
from django.test import override_settings

from lokdown.checks import (
    ACCOUNT_ADAPTER_CHECK_ID,
    SOCIALAUTH_ADAPTER_CHECK_ID,
    SOCIALAUTH_SITE_ID_CHECK_ID,
    check_account_adapter,
    check_socialauth_adapter,
    check_socialauth_site_id,
)


@pytest.mark.django_db
class TestSocialauthChecks:
    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=True,
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_site_id_warns_when_missing(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        monkeypatch.delattr(settings, "SITE_ID", raising=False)
        warnings = check_socialauth_site_id(None)
        assert len(warnings) == 1
        assert warnings[0].id == SOCIALAUTH_SITE_ID_CHECK_ID

    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=True,
        SITE_ID=1,
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_site_id_ok_when_set(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        assert check_socialauth_site_id(None) == []

    def test_no_warnings_when_socialauth_not_configured(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        with override_settings(SOCIALACCOUNT_PROVIDERS={}):
            assert check_socialauth_site_id(None) == []
            assert check_socialauth_adapter(None) == []
            assert check_account_adapter(None) == []

    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=True,
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_adapter_warns_when_not_lokdown_adapter(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        with override_settings(SOCIALACCOUNT_ADAPTER="allauth.socialaccount.adapter.DefaultSocialAccountAdapter"):
            warnings = check_socialauth_adapter(None)
        assert len(warnings) == 1
        assert warnings[0].id == SOCIALAUTH_ADAPTER_CHECK_ID

    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=True,
        SOCIALACCOUNT_ADAPTER="lokdown.socialauth.adapters.CustomSocialAccountAdapter",
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_adapter_ok_with_lokdown_adapter(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        assert check_socialauth_adapter(None) == []

    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=True,
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_account_adapter_warns_when_not_lokdown_adapter(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        with override_settings(ACCOUNT_ADAPTER="allauth.account.adapter.DefaultAccountAdapter"):
            warnings = check_account_adapter(None)
        assert len(warnings) == 1
        assert warnings[0].id == ACCOUNT_ADAPTER_CHECK_ID

    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=True,
        ACCOUNT_ADAPTER="lokdown.socialauth.adapters.CustomAccountAdapter",
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_account_adapter_ok_with_lokdown_adapter(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        assert check_account_adapter(None) == []

    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=False,
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_no_warnings_when_socialauth_feature_disabled(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        monkeypatch.delattr(settings, "SITE_ID", raising=False)
        assert check_socialauth_site_id(None) == []
        assert check_socialauth_adapter(None) == []
        assert check_account_adapter(None) == []

    @override_settings(
        LOKDOWN_SOCIALAUTH_ENABLED=True,
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_checks_registered_with_run_checks(self, monkeypatch):
        from django.conf import settings

        monkeypatch.delattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", raising=False)
        monkeypatch.delattr(settings, "SITE_ID", raising=False)
        results = run_checks()
        assert any(r.id == SOCIALAUTH_SITE_ID_CHECK_ID for r in results)
