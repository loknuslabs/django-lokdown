from unittest.mock import MagicMock

import pytest
from django.utils import timezone
from datetime import timedelta
from rest_framework import status

from lokdown.helpers.auth_flow_helper import (
    complete_login_with_tokens,
    create_authentication_session,
    disable_user_2fa,
    initiate_password_login,
    validate_session_data,
    verify_second_factor,
)
from lokdown.helpers.totp_helper import get_or_create_totp
from lokdown.models import LoginSession
from lokdown.helpers.backup_codes_helper import get_or_create_backup_codes


@pytest.mark.django_db
class TestCreateAuthenticationSession:
    def test_creates_session_with_metadata(self, user):
        request = MagicMock()
        request.META = {"HTTP_USER_AGENT": "pytest", "REMOTE_ADDR": "127.0.0.1"}
        session_id = create_authentication_session(user, request)
        session = LoginSession.objects.get(session_id=session_id)
        assert session.requires_2fa is True
        assert session.user_agent == "pytest"


@pytest.mark.django_db
class TestInitiatePasswordLogin:
    def test_returns_tokens_when_2fa_off(self, user):
        payload = initiate_password_login(user, None)
        assert payload["requires_2fa"] is False
        assert "access_token" in payload

    def test_returns_pre_2fa_session_when_totp_enabled(self, user_with_totp):
        payload = initiate_password_login(user_with_totp, None)
        assert payload["requires_2fa"] is True
        assert payload["totp_enabled"] is True
        assert LoginSession.objects.filter(session_id=payload["session_id"]).exists()


@pytest.mark.django_db
class TestVerifySecondFactor:
    def test_totp_success(self, user_with_totp, login_session, valid_totp_token):
        request = MagicMock()
        request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "pytest"}
        result = verify_second_factor(
            login_session.session_id,
            valid_totp_token,
            None,
            None,
            request,
        )
        assert isinstance(result, LoginSession)
        result.refresh_from_db()
        assert result.totp_verified is True

    def test_invalid_totp_returns_401(self, login_session):
        request = MagicMock()
        request.META = {}
        result = verify_second_factor(login_session.session_id, "000000", None, None, request)
        assert result.status_code == status.HTTP_401_UNAUTHORIZED

    def test_backup_code_success(self, user_with_totp, login_session):
        request = MagicMock()
        request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "pytest"}
        result = verify_second_factor(login_session.session_id, None, None, "BACKUP01", request)
        assert isinstance(result, LoginSession)

    def test_expired_session_returns_400(self, user_with_totp):
        session = LoginSession.objects.create(
            user=user_with_totp,
            session_id="expired-session",
            requires_2fa=True,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        request = MagicMock()
        request.META = {}
        result = verify_second_factor(session.session_id, "123456", None, None, request)
        assert result.status_code == status.HTTP_400_BAD_REQUEST

    def test_reused_session_returns_400(self, login_session, valid_totp_token):
        login_session.is_authenticated = True
        login_session.save()
        request = MagicMock()
        request.META = {}
        result = verify_second_factor(login_session.session_id, valid_totp_token, None, None, request)
        assert result.status_code == status.HTTP_400_BAD_REQUEST

    def test_no_method_returns_400(self, login_session):
        request = MagicMock()
        request.META = {}
        result = verify_second_factor(login_session.session_id, None, None, None, request)
        assert result.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestCompleteLoginWithTokens:
    def test_marks_session_authenticated(self, login_session):
        payload = complete_login_with_tokens(login_session, None, key_style="rest")
        login_session.refresh_from_db()
        assert login_session.is_authenticated is True
        assert "access_token" in payload

    def test_simplejwt_key_style(self, login_session):
        payload = complete_login_with_tokens(login_session, None, key_style="simplejwt")
        assert "access" in payload
        assert "refresh" in payload


@pytest.mark.django_db
class TestDisableUser2fa:
    def test_clears_all_factors(self, user_with_totp):
        disable_user_2fa(user_with_totp)
        two_fa = get_or_create_totp(user_with_totp)
        two_fa.refresh_from_db()
        assert two_fa.totp_secret is None
        assert user_with_totp.passkey_credentials.count() == 0
        assert get_or_create_backup_codes(user_with_totp).codes == []


@pytest.mark.django_db
class TestValidateSessionData:
    def test_missing_id(self):
        session, error = validate_session_data(None)
        assert session is None
        assert error is not None
