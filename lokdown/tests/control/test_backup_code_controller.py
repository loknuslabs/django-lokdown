import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestBackupCodeController:
    def test_verify_backup_code_endpoint(self, api_client, user_with_totp):
        init = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        response = api_client.post(
            reverse("lokdown:verify_backup_code"),
            {"session_id": init.data["session_id"], "backup_code": "BACKUP01"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access_token" in response.data
        assert response.data.get("message")

    def test_verify_backup_invalid_code(self, api_client, user_with_totp):
        init = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "testuser", "password": "testpass123"},
            format="json",
        )
        response = api_client.post(
            reverse("lokdown:verify_backup_code"),
            {"session_id": init.data["session_id"], "backup_code": "INVALID0"},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
