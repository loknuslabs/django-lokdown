import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from lokdown.helpers.api_key_helper import create_user_api_key, list_user_api_keys


@pytest.mark.django_db
class TestApiKeyController:
    def test_create_and_list(self, auth_client):
        create = auth_client.post(
            reverse("lokdown:manage_api_keys"),
            {"name": "CI token", "expires_in_days": 30},
            format="json",
        )
        assert create.status_code == status.HTTP_201_CREATED
        assert "api_key" in create.data
        assert create.data["prefix"].startswith("lk_")

        listing = auth_client.get(reverse("lokdown:manage_api_keys"))
        assert listing.status_code == status.HTTP_200_OK
        assert len(listing.data["api_keys"]) == 1
        assert "api_key" not in listing.data["api_keys"][0]

    def test_revoke(self, auth_client):
        create = auth_client.post(reverse("lokdown:manage_api_keys"), {}, format="json")
        key_id = create.data["id"]
        response = auth_client.delete(reverse("lokdown:revoke_api_key", args=[key_id]))
        assert response.status_code == status.HTTP_200_OK

        listing = auth_client.get(reverse("lokdown:manage_api_keys"))
        assert listing.data["api_keys"] == []

    @override_settings(LOKDOWN_API_KEYS_ENABLED=False)
    def test_disabled_returns_403(self, auth_client):
        response = auth_client.get(reverse("lokdown:manage_api_keys"))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_cannot_revoke_other_users_key(self, auth_client, other_user):
        api_key, _raw = create_user_api_key(other_user)
        response = auth_client.delete(reverse("lokdown:revoke_api_key", args=[api_key.id]))
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert list_user_api_keys(other_user) == [api_key]

    def test_staff_can_revoke_other_users_key(self, user, other_user):
        api_key, _raw = create_user_api_key(other_user)
        user.is_staff = True
        user.save(update_fields=["is_staff"])
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}")
        response = client.delete(reverse("lokdown:revoke_api_key", args=[api_key.id]))
        assert response.status_code == status.HTTP_200_OK
        assert list_user_api_keys(other_user) == []
