"""Checks must not import allauth when it is absent from INSTALLED_APPS."""

from django.test import override_settings

from lokdown.checks import check_account_adapter, check_socialauth_adapter, check_socialauth_site_id


class TestChecksWithoutAllauth:
    @override_settings(
        INSTALLED_APPS=["django.contrib.auth", "lokdown"],
        SOCIALACCOUNT_PROVIDERS={"google": {"APPS": [{"client_id": "a", "secret": "b"}]}},
    )
    def test_socialauth_checks_skip_when_allauth_not_installed(self):
        assert check_socialauth_site_id(None) == []
        assert check_socialauth_adapter(None) == []
        assert check_account_adapter(None) == []
