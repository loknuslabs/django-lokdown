from datetime import timedelta
from unittest.mock import patch

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from lokdown.models import LoginSession, PasskeyCredential


@pytest.mark.django_db
class TestPasskeyController:
    @patch("lokdown.control.passkey_controller.begin_passkey_registration")
    def test_setup_passkey(self, mock_begin, auth_client):
        mock_begin.return_value = {"session_id": "sess-1", "options": {"challenge": "abc"}}
        response = auth_client.post(reverse("lokdown:setup_passkey"), {}, format="json")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["session_id"] == "sess-1"
        mock_begin.assert_called_once()

    @patch("lokdown.control.passkey_controller.complete_passkey_registration")
    def test_verify_passkey_setup_success(self, mock_complete, auth_client):
        mock_complete.return_value = (True, None, ["BACKUP01", "BACKUP02"])
        response = auth_client.post(
            reverse("lokdown:verify_passkey_setup"),
            {"session_id": "sess-1", "passkey_response": {"id": "x"}},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["backup_codes"] == ["BACKUP01", "BACKUP02"]
        mock_complete.assert_called_once()

    @patch("lokdown.control.passkey_controller.complete_passkey_registration")
    def test_verify_passkey_setup_generic_error(self, mock_complete, auth_client):
        mock_complete.side_effect = ValueError("internal webauthn detail")
        response = auth_client.post(
            reverse("lokdown:verify_passkey_setup"),
            {"session_id": "sess-1", "passkey_response": {"id": "x"}},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.data["error"] == "Passkey setup failed"
        assert "internal webauthn detail" not in response.data["error"]

    @patch("lokdown.control.passkey_controller.begin_passkey_authentication")
    def test_get_passkey_auth_options(self, mock_begin, api_client, user_with_passkey):
        session = LoginSession.objects.create(
            user=user_with_passkey,
            session_id="passkey-login-session",
            requires_2fa=True,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        mock_begin.return_value = {
            "challenge": "Y2hhbGxlbmdl",
            "rp_id": "localhost",
            "timeout": 60000,
            "options": {},
        }
        response = api_client.post(
            reverse("lokdown:get_passkey_auth_options"),
            {"session_id": session.session_id},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "challenge" in response.data

    def test_get_passkey_credentials(self, auth_client, user_with_passkey):
        response = auth_client.get(reverse("lokdown:get_passkey_credentials"))
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 1

    def test_remove_passkey_credential(self, auth_client, user_with_passkey):
        cred_id = user_with_passkey.passkey_credentials.first().credential_id
        url = reverse("lokdown:remove_passkey_credential") + f"?credential_id={cred_id}"
        response = auth_client.delete(url)
        assert response.status_code == status.HTTP_200_OK
        assert PasskeyCredential.objects.filter(user=user_with_passkey).count() == 0

    @patch("lokdown.control.passkey_controller.admin_passkey_auth_options_payload")
    def test_admin_2fa_auth_options(self, mock_payload, api_client, login_session):
        mock_payload.return_value = {
            "challenge": "Y2hhbGxlbmdl",
            "rp_id": "localhost",
            "timeout": 60000,
        }
        session = api_client.session
        session["admin_2fa_session_id"] = login_session.session_id
        session.save()
        response = api_client.post(reverse("lokdown:admin_2fa_auth_options"))
        assert response.status_code == status.HTTP_200_OK
        assert "challenge" in response.data
