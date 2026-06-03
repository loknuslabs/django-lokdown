import pyotp
import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework import status

from lokdown.helpers.totp_helper import get_or_create_totp


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

    def test_verify_totp_setup_enrolls_user(self, auth_client, user):
        setup = auth_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        secret = setup.data["secret"]
        token = pyotp.TOTP(secret).now()
        response = auth_client.post(
            reverse("lokdown:verify_totp_setup"),
            {"totp_token": token, "secret": secret},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["backup_codes"]) == settings.BACKUP_CODES_COUNT
        two_fa = get_or_create_totp(user)
        two_fa.refresh_from_db()
        assert two_fa.totp_secret == secret

    def test_verify_totp_invalid_token(self, auth_client):
        setup = auth_client.post(reverse("lokdown:setup_totp"), {}, format="json")
        response = auth_client.post(
            reverse("lokdown:verify_totp_setup"),
            {"totp_token": "000000", "secret": setup.data["secret"]},
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
