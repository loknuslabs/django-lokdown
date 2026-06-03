import pytest
from django.utils import timezone
from datetime import timedelta

from lokdown.helpers.session_helper import (
    create_authentication_session,
    get_session,
    validate_session_data,
)
from lokdown.models import LoginSession


@pytest.mark.django_db
class TestSessionHelper:
    def test_get_session_is_alias_for_verify_second_factor(self, login_session, valid_totp_token):
        request = type("R", (), {"META": {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "x"}})()
        result = get_session(login_session.session_id, valid_totp_token, None, None, request)
        assert isinstance(result, LoginSession)

    def test_validate_session_data_expired(self, user):
        session_id = create_authentication_session(user)
        session = LoginSession.objects.get(session_id=session_id)
        session.expires_at = timezone.now() - timedelta(minutes=1)
        session.save()
        found, error = validate_session_data(session_id)
        assert found is None
        assert "expired" in error.lower() or "Invalid" in error
