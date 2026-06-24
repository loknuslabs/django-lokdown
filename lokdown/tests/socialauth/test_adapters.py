import pytest
from django.contrib.auth.models import User
from django.test import override_settings

from lokdown.socialauth.adapters import CustomAccountAdapter, CustomSocialAccountAdapter


class _FakeSocialLogin:
    def __init__(self, user=None, account=None):
        self.user = user if user is not None else User()
        self.account = account


@pytest.mark.django_db
class TestCustomSocialAccountAdapter:
    @override_settings(LOKDOWN_ALLOW_PUBLIC_REGISTRATION=True)
    def test_is_open_for_signup_when_enabled(self):
        adapter = CustomSocialAccountAdapter()
        assert adapter.is_open_for_signup(None, _FakeSocialLogin()) is True

    @override_settings(LOKDOWN_ALLOW_PUBLIC_REGISTRATION=False)
    def test_is_open_for_signup_when_disabled(self):
        adapter = CustomSocialAccountAdapter()
        assert adapter.is_open_for_signup(None, _FakeSocialLogin()) is False

    def test_populate_user_sets_username_from_email(self):
        adapter = CustomSocialAccountAdapter()
        user = User()
        result = adapter.populate_user(
            None,
            _FakeSocialLogin(user=user),
            {"email": "new.user@example.com"},
        )
        assert result.email == "new.user@example.com"
        assert result.username == "new.user@example.com"

    def test_populate_user_deduplicates_username_collision(self):
        User.objects.create_user(username="taken@example.com", email="other@example.com", password="x")
        adapter = CustomSocialAccountAdapter()
        user = User()
        result = adapter.populate_user(
            None,
            _FakeSocialLogin(user=user),
            {"email": "taken@example.com"},
        )
        assert result.username == "taken@example.com_1"

    def test_populate_user_uses_data_email_when_user_email_empty(self):
        adapter = CustomSocialAccountAdapter()
        user = User()
        result = adapter.populate_user(
            None,
            _FakeSocialLogin(user=user),
            {"email": "from.provider@example.com"},
        )
        assert result.username == "from.provider@example.com"

    def test_populate_user_skips_username_when_no_email(self):
        adapter = CustomSocialAccountAdapter()
        user = User()
        result = adapter.populate_user(
            None,
            _FakeSocialLogin(user=user),
            {"username": "provider_handle"},
        )
        assert result.username == "provider_handle"

    def test_populate_user_truncates_long_email_for_username(self):
        adapter = CustomSocialAccountAdapter()
        long_local = "a" * 200
        long_email = f"{long_local}@example.com"
        user = User()
        result = adapter.populate_user(
            None,
            _FakeSocialLogin(user=user),
            {"email": long_email},
        )
        assert len(result.username) <= 150


class TestCustomAccountAdapter:
    @override_settings(LOKDOWN_ALLOW_PUBLIC_REGISTRATION=True)
    def test_is_open_for_signup_when_enabled(self):
        adapter = CustomAccountAdapter()
        assert adapter.is_open_for_signup(None) is True

    @override_settings(LOKDOWN_ALLOW_PUBLIC_REGISTRATION=False)
    def test_is_open_for_signup_when_disabled(self):
        adapter = CustomAccountAdapter()
        assert adapter.is_open_for_signup(None) is False
