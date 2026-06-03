import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from lokdown.helpers.rate_limit_helper import (
    check_login_init_rate_limit,
    check_totp_verify_rate_limit,
)


@pytest.mark.django_db
class TestRateLimitHelper:
    @override_settings(LOGIN_INIT_RATE_LIMIT="2/m")
    def test_login_init_rate_limited_by_ip(self, rf):
        request = rf.post("/auth/login/init")
        request.META["REMOTE_ADDR"] = "10.0.0.1"

        assert check_login_init_rate_limit(request, "alice") is None
        assert check_login_init_rate_limit(request, "alice") is None
        response = check_login_init_rate_limit(request, "alice")
        assert response is not None
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    @override_settings(TOTP_VERIFY_RATE_LIMIT="2/m")
    def test_totp_verify_rate_limited_by_username(self, rf):
        request = rf.post("/auth/login/verify")
        request.META["REMOTE_ADDR"] = "10.0.0.2"

        assert check_totp_verify_rate_limit(request, "alice") is None
        assert check_totp_verify_rate_limit(request, "alice") is None
        response = check_totp_verify_rate_limit(request, "alice")
        assert response is not None
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.django_db
class TestAuthControllerRateLimits:
    @override_settings(LOGIN_INIT_RATE_LIMIT="2/m")
    def test_login_init_returns_429_when_rate_limited(self, api_client, user):
        url = reverse("lokdown:login_init")
        payload = {"username": "testuser", "password": "testpass123"}

        for _ in range(2):
            api_client.post(url, payload, format="json", REMOTE_ADDR="10.0.0.3")

        response = api_client.post(url, payload, format="json", REMOTE_ADDR="10.0.0.3")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.data["error"] == "Too many authentication attempts"

    @override_settings(TOTP_VERIFY_RATE_LIMIT="2/m")
    def test_login_verify_totp_returns_429_when_rate_limited(self, api_client, user_with_totp):
        init = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "testuser", "password": "testpass123"},
            format="json",
            REMOTE_ADDR="10.0.0.4",
        )
        session_id = init.data["session_id"]
        url = reverse("lokdown:login_verify")
        payload = {"session_id": session_id, "totp_token": "000000"}

        for _ in range(2):
            api_client.post(url, payload, format="json", REMOTE_ADDR="10.0.0.4")

        response = api_client.post(url, payload, format="json", REMOTE_ADDR="10.0.0.4")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.data["error"] == "Too many authentication attempts"
