import pyotp
import pytest
from django.contrib.auth.models import User
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from lokdown.helpers.backup_codes_helper import get_or_create_backup_codes
from lokdown.helpers.totp_helper import get_or_create_totp
from lokdown.models import LoginSession, PasskeyCredential


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def user(db):
    return User.objects.create_user(username="testuser", password="testpass123", email="test@example.com")


@pytest.fixture
def other_user(db):
    return User.objects.create_user(username="otheruser", password="otherpass123")


@pytest.fixture
def totp_secret():
    return pyotp.random_base32()


@pytest.fixture
def user_with_totp(user, totp_secret):
    two_fa = get_or_create_totp(user)
    two_fa.totp_secret = totp_secret
    two_fa.save(update_fields=["totp_secret"])
    backup = get_or_create_backup_codes(user)
    backup.codes = ["BACKUP01", "BACKUP02"]
    backup.save(update_fields=["codes"])
    return user


@pytest.fixture
def valid_totp_token(totp_secret):
    return pyotp.TOTP(totp_secret).now()


@pytest.fixture
def user_with_passkey(user, db):
    from webauthn.helpers import bytes_to_base64url

    PasskeyCredential.objects.create(
        user=user,
        credential_id=bytes_to_base64url(b"test-credential-id"),
        public_key="dGVzdC1wdWJsaWMta2V5",
        sign_count=0,
        rp_id="localhost",
        user_handle=str(user.id),
    )
    return user


@pytest.fixture
def login_session(user_with_totp):
    return LoginSession.objects.create(
        user=user_with_totp,
        session_id="test-session-uuid-0001",
        requires_2fa=True,
        expires_at=timezone.now() + timedelta(minutes=10),
        ip_address="127.0.0.1",
        user_agent="pytest",
    )


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def auth_client(user):
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


@pytest.fixture
def auth_client_totp(user_with_totp):
    client = APIClient()
    token = RefreshToken.for_user(user_with_totp)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client
