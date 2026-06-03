import pytest
from django.urls import reverse
from rest_framework import status

from lokdown.helpers.totp_helper import has_totp_enabled


@pytest.mark.django_db
class TestTwoFaController:
    def test_get_2fa_status_disabled(self, auth_client, user):
        response = auth_client.get(reverse("lokdown:get_2fa_status"))
        assert response.status_code == status.HTTP_200_OK
        assert response.data["is_enabled"] is False

    def test_get_2fa_status_enabled(self, auth_client_totp, user_with_totp):
        response = auth_client_totp.get(reverse("lokdown:get_2fa_status"))
        assert response.status_code == status.HTTP_200_OK
        assert response.data["is_enabled"] is True
        assert response.data["totp_enabled"] is True

    def test_disable_2fa(self, auth_client_totp, user_with_totp):
        response = auth_client_totp.post(reverse("lokdown:disable_2fa"), format="json")
        assert response.status_code == status.HTTP_200_OK
        assert has_totp_enabled(user_with_totp) is False
