import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from lokdown.helpers.backup_codes_helper import store_backup_codes
from lokdown.helpers.passkey_helper import has_passkey_enabled
from lokdown.helpers.totp_helper import has_totp_enabled
from lokdown.models import LoginSession


@pytest.fixture
def oauth_api_client():
    return APIClient()


def _assert_oauth_callback_issues_jwt(response, user):
    assert response.status_code == 200
    assert response.data["requires_2fa"] is False
    assert "access_token" in response.data
    assert "refresh_token" in response.data
    assert "session_id" not in response.data
    assert LoginSession.objects.filter(user=user).count() == 0


@pytest.mark.django_db
class TestOAuthApiEndpoints:
    def test_oauth_providers_lists_configured_providers(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_providers"))
        assert response.status_code == 200
        ids = {p["provider"] for p in response.data["providers"]}
        assert "google" in ids
        assert "dummy" in ids
        assert all(p["redirect_url"].startswith("http") for p in response.data["providers"])
        assert all(p["redirect_method"] == "POST" for p in response.data["providers"])

    def test_oauth_providers_respects_callback_url_query(self, oauth_api_client):
        response = oauth_api_client.get(
            reverse("lokdown:oauth_providers"),
            {"callback_url": "http://localhost:5173/custom/callback"},
        )
        assert response.status_code == 200
        assert response.data["providers"][0]["callback_url"] == "http://localhost:5173/custom/callback"

    def test_oauth_providers_accepts_legacy_next_query(self, oauth_api_client):
        response = oauth_api_client.get(
            reverse("lokdown:oauth_providers"),
            {"next": "/custom/callback"},
        )
        assert response.status_code == 200
        assert response.data["providers"][0]["callback_url"].endswith("/custom/callback")

    @override_settings(LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS=["http://localhost:5173"])
    def test_oauth_providers_rejects_disallowed_callback_url(self, oauth_api_client):
        response = oauth_api_client.get(
            reverse("lokdown:oauth_providers"),
            {"callback_url": "https://evil.example/callback"},
        )
        assert response.status_code == 400
        assert "callback_url" in response.data

    def test_oauth_provider_login_google(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_provider_login", kwargs={"provider": "google"}))
        assert response.status_code == 200
        assert response.data["provider"] == "google"
        assert "/_allauth/browser/v1/auth/provider/redirect" in response.data["redirect_url"]
        assert response.data["redirect_method"] == "POST"

    def test_oauth_provider_login_unknown_returns_404(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_provider_login", kwargs={"provider": "notreal"}))
        assert response.status_code == 404

    def test_oauth_callback_bridge_requires_auth(self, oauth_api_client):
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code in (401, 403)

    def test_oauth_callback_bridge_rejects_get(self, oauth_api_client, user):
        oauth_api_client.force_login(user)
        response = oauth_api_client.get(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code == 405

    def test_oauth_callback_bridge_accepts_django_session_cookie(self, oauth_api_client, user):
        oauth_api_client.force_login(user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, user)

    def test_oauth_callback_bridge_returns_jwt_without_2fa(self, oauth_api_client, user):
        oauth_api_client.force_authenticate(user=user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, user)

    def test_oauth_callback_bridge_skips_totp_and_backup_codes(self, oauth_api_client, user_with_totp):
        assert has_totp_enabled(user_with_totp) is True
        oauth_api_client.force_login(user_with_totp)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, user_with_totp)

    def test_oauth_callback_bridge_skips_passkey(self, oauth_api_client, user_with_passkey):
        assert has_passkey_enabled(user_with_passkey) is True
        oauth_api_client.force_login(user_with_passkey)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, user_with_passkey)

    def test_oauth_callback_bridge_skips_backup_codes_only_user(self, oauth_api_client, user):
        store_backup_codes(user, ["BACKUP01", "BACKUP02"])
        oauth_api_client.force_login(user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, user)

    @override_settings(ADMIN_2FA_REQUIRED=True)
    def test_oauth_callback_bridge_skips_staff_2fa_setup(self, oauth_api_client, staff_user):
        oauth_api_client.force_login(staff_user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, staff_user)

    @override_settings(ADMIN_2FA_REQUIRED=True)
    def test_oauth_callback_bridge_skips_staff_totp_verify(self, oauth_api_client, staff_user_with_totp):
        assert has_totp_enabled(staff_user_with_totp) is True
        oauth_api_client.force_login(staff_user_with_totp)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, staff_user_with_totp)

    @override_settings(ADMIN_2FA_REQUIRED=True)
    def test_oauth_callback_bridge_skips_staff_passkey_verify(self, oauth_api_client, staff_user):
        from webauthn.helpers import bytes_to_base64url

        from lokdown.models import PasskeyCredential

        PasskeyCredential.objects.create(
            user=staff_user,
            credential_id=bytes_to_base64url(b"staff-credential-id"),
            public_key="dGVzdC1wdWJsaWMta2V5",
            sign_count=0,
            rp_id="localhost",
            user_handle=str(staff_user.id),
        )
        assert has_passkey_enabled(staff_user) is True
        oauth_api_client.force_login(staff_user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, staff_user)

    @override_settings(ADMIN_2FA_REQUIRED=False)
    def test_oauth_callback_bridge_staff_jwt_when_admin_2fa_not_required(self, oauth_api_client, staff_user):
        oauth_api_client.force_login(staff_user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, staff_user)

    def test_oauth_callback_jwt_works_on_protected_endpoint(self, oauth_api_client, user_with_totp):
        oauth_api_client.force_login(user_with_totp)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        _assert_oauth_callback_issues_jwt(response, user_with_totp)

        authed = APIClient()
        authed.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access_token']}")
        status_response = authed.get(reverse("lokdown:get_2fa_status"))
        assert status_response.status_code == 200
        assert status_response.data["totp_enabled"] is True

    @override_settings(INSTALLED_APPS=["django.contrib.auth", "rest_framework", "lokdown"])
    def test_oauth_providers_503_without_allauth(self, oauth_api_client):
        response = oauth_api_client.get(reverse("lokdown:oauth_providers"))
        assert response.status_code == 503

    @override_settings(LOKDOWN_SOCIALAUTH_ENABLED=False)
    def test_oauth_disabled_returns_403(self, oauth_api_client, user):
        response = oauth_api_client.get(reverse("lokdown:oauth_providers"))
        assert response.status_code == 403

        response = oauth_api_client.get(reverse("lokdown:oauth_provider_login", kwargs={"provider": "google"}))
        assert response.status_code == 403

        oauth_api_client.force_authenticate(user=user)
        response = oauth_api_client.post(reverse("lokdown:oauth_callback_bridge"))
        assert response.status_code == 403
