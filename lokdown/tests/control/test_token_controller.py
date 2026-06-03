import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestTokenController:
    def test_token_obtain_without_2fa(self, api_client, user):
        response = api_client.post(
            reverse("lokdown:token_obtain_pair"),
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    def test_token_obtain_with_2fa_returns_401_and_session(self, api_client, user_with_totp):
        response = api_client.post(
            reverse("lokdown:token_obtain_pair"),
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.data["requires_2fa"] is True
        assert "session_id" in response.data

    def test_token_verify_2fa_completes_login(self, api_client, user_with_totp, valid_totp_token):
        init = api_client.post(
            reverse("lokdown:token_obtain_pair"),
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        response = api_client.post(
            reverse("lokdown:token_verify_2fa"),
            {"session_id": init.data["session_id"], "totp_token": valid_totp_token},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data
