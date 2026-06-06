import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from lokdown.helpers.api_key_helper import create_user_api_key


@pytest.mark.django_db
class TestApiKeyAuthentication:
    def test_api_key_authenticates_protected_endpoint(self, user):
        _api_key, raw = create_user_api_key(user, name="auth test")
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Api-Key {raw}")
        response = client.get(reverse("lokdown:get_2fa_status"))
        assert response.status_code == status.HTTP_200_OK

    def test_invalid_api_key_rejected(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Api-Key lk_deadbeef.not-a-real-key")
        response = client.get(reverse("lokdown:get_2fa_status"))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @override_settings(LOKDOWN_API_KEYS_ENABLED=False)
    def test_disabled_skips_api_key_auth(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Api-Key lk_deadbeef.not-a-real-key")
        response = client.get(reverse("lokdown:get_2fa_status"))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
