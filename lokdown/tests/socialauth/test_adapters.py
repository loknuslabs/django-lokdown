import pytest
from allauth.account.models import EmailAddress
from allauth.socialaccount.internal.flows.email_authentication import wipe_password
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.test import RequestFactory, override_settings

from lokdown.socialauth.adapters import CustomAccountAdapter, CustomSocialAccountAdapter


class _FakeSocialLogin:
    def __init__(self, user=None, account=None, authenticated_email=None):
        self.user = user if user is not None else User()
        self.account = account
        self._did_authenticate_by_email = authenticated_email


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

    def test_pre_social_login_verifies_email_so_password_is_not_wiped(self):
        user = User.objects.create_user(
            username="staffuser",
            password="staffpass123",
            email="staff@example.com",
            is_staff=True,
        )
        adapter = CustomSocialAccountAdapter()
        sociallogin = _FakeSocialLogin(user=user, authenticated_email="staff@example.com")

        adapter.pre_social_login(None, sociallogin)
        wipe_password(RequestFactory().get("/"), user, "staff@example.com")

        user.refresh_from_db()
        assert user.has_usable_password()
        assert user.check_password("staffpass123")
        assert authenticate(username="staffuser", password="staffpass123") == user
        address = EmailAddress.objects.get(user=user, email="staff@example.com")
        assert address.verified is True

    def test_pre_social_login_verifies_existing_unverified_email(self):
        user = User.objects.create_user(
            username="localuser",
            password="localpass123",
            email="local@example.com",
        )
        EmailAddress.objects.create(
            user=user,
            email="local@example.com",
            verified=False,
            primary=True,
        )
        adapter = CustomSocialAccountAdapter()
        adapter.pre_social_login(
            None,
            _FakeSocialLogin(user=user, authenticated_email="local@example.com"),
        )
        wipe_password(RequestFactory().get("/"), user, "local@example.com")

        user.refresh_from_db()
        assert user.has_usable_password()
        address = EmailAddress.objects.get(user=user, email="local@example.com")
        assert address.verified is True

    def test_pre_social_login_skips_when_email_auth_did_not_match(self):
        user = User.objects.create_user(
            username="untouched",
            password="keeppass123",
            email="untouched@example.com",
        )
        adapter = CustomSocialAccountAdapter()
        adapter.pre_social_login(None, _FakeSocialLogin(user=user))

        assert not EmailAddress.objects.filter(user=user).exists()
        assert user.check_password("keeppass123")

    def test_pre_social_login_preserves_password_even_if_allauth_wipes(self):
        user = User.objects.create_user(
            username="staffwipe",
            password="staffpass123",
            email="staffwipe@example.com",
            is_staff=True,
        )
        adapter = CustomSocialAccountAdapter()
        adapter.pre_social_login(None, _FakeSocialLogin(user=user))
        wipe_password(RequestFactory().get("/"), user, "staffwipe@example.com")

        user.refresh_from_db()
        assert user.has_usable_password()
        assert user.check_password("staffpass123")
        assert authenticate(username="staffwipe", password="staffpass123") == user


class TestCustomAccountAdapter:
    @override_settings(LOKDOWN_ALLOW_PUBLIC_REGISTRATION=True)
    def test_is_open_for_signup_when_enabled(self):
        adapter = CustomAccountAdapter()
        assert adapter.is_open_for_signup(None) is True

    @override_settings(LOKDOWN_ALLOW_PUBLIC_REGISTRATION=False)
    def test_is_open_for_signup_when_disabled(self):
        adapter = CustomAccountAdapter()
        assert adapter.is_open_for_signup(None) is False
