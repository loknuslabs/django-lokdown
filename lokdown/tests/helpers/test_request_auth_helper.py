from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone
from rest_framework.test import APIRequestFactory
from rest_framework_simplejwt.tokens import RefreshToken

from lokdown.helpers.request_auth_helper import (
    clear_admin_pending_session_id,
    extract_pending_session_id,
    resolve_pending_login_session,
    resolve_pending_session_id,
    store_admin_pending_session_id,
)
from lokdown.models import LoginSession


@pytest.mark.django_db
class TestRequestAuthHelper:
    def test_extract_pending_session_id_from_body(self):
        request = MagicMock()
        request.data = {"session_id": "from-body"}
        request.POST = {}
        request.GET = {}
        assert extract_pending_session_id(request) == "from-body"

    def test_resolve_pending_session_id_from_django_session(self, login_session):
        factory = APIRequestFactory()
        request = factory.post("/")
        request.session = {}
        store_admin_pending_session_id(request, login_session.session_id)
        assert resolve_pending_session_id(request) == login_session.session_id

    def test_resolve_pending_session_id_from_bearer_user(self, user_with_totp):
        LoginSession.objects.create(
            user=user_with_totp,
            session_id="bearer-pending-session",
            requires_2fa=True,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        with patch(
            "lokdown.helpers.request_auth_helper.get_optional_authenticated_user",
            return_value=user_with_totp,
        ):
            request = MagicMock()
            request.data = {}
            request.POST = {}
            request.GET = {}
            request.session = {}
            assert resolve_pending_session_id(request) == "bearer-pending-session"

    def test_clear_admin_pending_session_id(self):
        request = MagicMock()
        request.session = {"admin_2fa_session_id": "abc"}
        clear_admin_pending_session_id(request)
        assert "admin_2fa_session_id" not in request.session
