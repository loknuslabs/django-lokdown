import pyotp
import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework import status

from lokdown.helpers.totp_helper import generate_totp_secret, get_or_create_totp, read_stored_secret


@pytest.mark.django_db
class TestTotpController:
    def test_setup_totp_requires_auth(self, api_client):
        response = api_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_setup_totp_returns_secret_and_qr(self, auth_client):
        response = auth_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        assert response.status_code == status.HTTP_200_OK
        assert "secret" in response.data
        assert "qr_code" in response.data
        assert "provisioning_uri" in response.data

    def test_setup_totp_stores_pending_secret_server_side(self, auth_client, user):
        response = auth_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        two_fa = get_or_create_totp(user)
        two_fa.refresh_from_db()
        assert read_stored_secret(two_fa.pending_totp_secret) == response.data["secret"]
        assert two_fa.totp_secret is None

    def test_setup_totp_rejects_when_already_enabled(self, auth_client_totp):
        response = auth_client_totp.post(reverse("lokdown:setup_totp"), {}, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["error"] == "TOTP is already enabled"

    def test_verify_totp_setup_enrolls_user(self, auth_client, user):
        setup = auth_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        secret = setup.data["secret"]
        token = pyotp.TOTP(secret).now()
        response = auth_client.post(
            reverse("lokdown:verify_totp_setup"),
            {"totp_token": token},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["backup_codes"]) == settings.BACKUP_CODES_COUNT
        two_fa = get_or_create_totp(user)
        two_fa.refresh_from_db()
        assert read_stored_secret(two_fa.totp_secret) == secret
        assert two_fa.pending_totp_secret is None

    def test_verify_totp_rejects_client_supplied_secret(self, auth_client, user):
        setup = auth_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        server_secret = setup.data["secret"]
        attacker_secret = generate_totp_secret()
        token = pyotp.TOTP(server_secret).now()
        response = auth_client.post(
            reverse("lokdown:verify_totp_setup"),
            {"totp_token": token, "secret": attacker_secret},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        two_fa = get_or_create_totp(user)
        two_fa.refresh_from_db()
        assert read_stored_secret(two_fa.totp_secret) == server_secret
        assert read_stored_secret(two_fa.totp_secret) != attacker_secret

    def test_verify_totp_without_pending_setup_fails(self, auth_client):
        attacker_secret = generate_totp_secret()
        token = pyotp.TOTP(attacker_secret).now()
        response = auth_client.post(
            reverse("lokdown:verify_totp_setup"),
            {"totp_token": token},
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["error"] == "No pending TOTP setup found"

    def test_verify_totp_invalid_token(self, auth_client):
        auth_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        response = auth_client.post(
            reverse("lokdown:verify_totp_setup"),
            {"totp_token": "000000"},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
