import pytest
from django.urls import reverse
from rest_framework import status

from lokdown.models import LoginSession


@pytest.mark.django_db
class TestAuthController:
    def test_login_init_invalid_credentials(self, api_client):
        url = reverse("lokdown:login_init")
        response = api_client.post(url, {"username": "nobody", "password": "wrong"}, format="json")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_init_without_2fa_returns_tokens(self, api_client, user):
        url = reverse("lokdown:login_init")
        response = api_client.post(
            url,
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["requires_2fa"] is False
        assert "access_token" in response.data

    def test_login_init_with_2fa_returns_session(self, api_client, user_with_totp):
        url = reverse("lokdown:login_init")
        response = api_client.post(
            url,
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["requires_2fa"] is True
        assert "session_id" in response.data

    def test_login_verify_totp_flow(self, api_client, user_with_totp, valid_totp_token):
        init = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        session_id = init.data["session_id"]
        verify = api_client.post(
            reverse("lokdown:login_verify"),
            {"session_id": session_id, "totp_token": valid_totp_token},
            format="json",
        )
        assert verify.status_code == status.HTTP_200_OK
        assert "access_token" in verify.data
        assert LoginSession.objects.get(session_id=session_id).is_authenticated is True

    def test_login_verify_invalid_session(self, api_client):
        response = api_client.post(
            reverse("lokdown:login_verify"),
            {"session_id": "not-a-real-session", "totp_token": "123456"},
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
