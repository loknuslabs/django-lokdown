from datetime import timedelta

import pyotp
import pytest
from django.contrib.auth import BACKEND_SESSION_KEY
from django.contrib.auth.models import User
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from lokdown.helpers.totp_helper import get_or_create_totp, write_stored_secret
from lokdown.models import LoginSession


@pytest.fixture
def staff_with_totp(db):
    user = User.objects.create_user(username="staff2fa", password="staffpass123", is_staff=True)
    two_fa = get_or_create_totp(user)
    secret = pyotp.random_base32()
    two_fa.totp_secret = write_stored_secret(secret)
    two_fa.save(update_fields=["totp_secret"])
    return user, secret


@pytest.mark.django_db
class TestAdminLoginWithMultipleBackends:
    @override_settings(
        ADMIN_2FA_REQUIRED=True,
        AUTHENTICATION_BACKENDS=[
            "django.contrib.auth.backends.ModelBackend",
            "allauth.account.auth_backends.AuthenticationBackend",
        ],
    )
    def test_admin_2fa_verify_login_sets_backend(self, staff_with_totp):
        user, secret = staff_with_totp
        login_session = LoginSession.objects.create(
            user=user,
            session_id="admin-verify-test-session",
            requires_2fa=True,
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        client = Client()
        session_obj = client.session
        session_obj["admin_2fa_session_id"] = login_session.session_id
        session_obj.save()

        response = client.post(
            reverse("admin_2fa_verify"),
            {"totp_token": pyotp.TOTP(secret).now()},
        )
        assert response.status_code == 302
        assert response.url == reverse("admin:index")
        assert client.session.get(BACKEND_SESSION_KEY) == "django.contrib.auth.backends.ModelBackend"
