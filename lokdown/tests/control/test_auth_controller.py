import pyotp
import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch

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

    @override_settings(ADMIN_2FA_REQUIRED=True)
    def test_staff_first_login_requires_2fa_setup(self, api_client, staff_user):
        response = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "staffuser", "password": "staffpass123"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["requires_2fa"] is True
        assert response.data["requires_2fa_setup"] is True
        assert "session_id" in response.data
        assert "access_token" not in response.data

    @override_settings(ADMIN_2FA_REQUIRED=True)
    def test_staff_first_login_totp_setup_flow(self, api_client, staff_user):
        init = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "staffuser", "password": "staffpass123"},
            format="json",
        )
        setup = api_client.post(
            reverse("lokdown:login_setup_totp"),
            {"session_id": init.data["session_id"]},
            format="json",
        )
        assert setup.status_code == status.HTTP_200_OK
        assert "secret" in setup.data

        token = pyotp.TOTP(setup.data["secret"]).now()
        verify = api_client.post(
            reverse("lokdown:login_verify_totp_setup"),
            {"session_id": init.data["session_id"], "totp_token": token},
            format="json",
        )
        assert verify.status_code == status.HTTP_200_OK
        assert "access_token" in verify.data
        assert verify.data["backup_codes"]
        assert LoginSession.objects.get(session_id=init.data["session_id"]).is_authenticated is True

    @override_settings(ADMIN_2FA_REQUIRED=True)
    def test_staff_login_verify_rejects_backup_code_without_primary_2fa(self, api_client, staff_user):
        from lokdown.helpers.backup_codes_helper import store_backup_codes

        store_backup_codes(staff_user, ["BACKUP01", "BACKUP02"])
        init = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "staffuser", "password": "staffpass123"},
            format="json",
        )
        assert init.data["requires_2fa_setup"] is True

        verify = api_client.post(
            reverse("lokdown:login_verify"),
            {"session_id": init.data["session_id"], "backup_code": "BACKUP01"},
            format="json",
        )
        assert verify.status_code == status.HTTP_403_FORBIDDEN
        assert "Primary 2FA enrollment required" in verify.data["error"]

    @override_settings(ADMIN_2FA_REQUIRED=True)
    @patch("lokdown.helpers.auth_flow_helper.save_passkey_to_database", return_value=True)
    @patch("lokdown.helpers.auth_flow_helper.verify_passkey_registration")
    def test_staff_first_login_passkey_setup_flow(self, mock_verify, _mock_save, api_client, staff_user):
        mock_verify.return_value = object()

        init = api_client.post(
            reverse("lokdown:login_init"),
            {"username": "staffuser", "password": "staffpass123"},
            format="json",
        )
        setup = api_client.post(
            reverse("lokdown:login_setup_passkey"),
            {"session_id": init.data["session_id"]},
            format="json",
        )
        assert setup.status_code == status.HTTP_200_OK
        assert "options" in setup.data
        passkey_session_id = setup.data["session_id"]

        verify = api_client.post(
            reverse("lokdown:login_verify_passkey_setup"),
            {
                "session_id": passkey_session_id,
                "passkey_response": {
                    "id": "cred",
                    "rawId": "cred",
                    "type": "public-key",
                    "response": {},
                },
            },
            format="json",
        )
        assert verify.status_code == status.HTTP_200_OK
        assert "access_token" in verify.data
        assert verify.data["backup_codes"]
        assert LoginSession.objects.get(session_id=passkey_session_id).is_authenticated is True
