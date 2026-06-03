import pyotp
import pytest

from lokdown.helpers.totp_helper import (
    generate_totp_secret,
    get_or_create_totp,
    has_totp_enabled,
    setup_totp_complete,
    store_pending_totp_secret,
    verify_totp_login,
    verify_totp_token_setup,
)
from lokdown.helpers.backup_codes_helper import get_or_create_backup_codes


@pytest.mark.django_db
class TestTotpHelper:
    def test_has_totp_disabled_by_default(self, user):
        assert has_totp_enabled(user) is False

    def test_setup_and_verify_login(self, user, totp_secret):
        token = pyotp.TOTP(totp_secret).now()
        assert verify_totp_token_setup(totp_secret, token) is True
        assert setup_totp_complete(user, totp_secret) is True
        assert has_totp_enabled(user) is True
        assert len(get_or_create_backup_codes(user).codes) == 4

        login_token = pyotp.TOTP(totp_secret).now()
        assert verify_totp_login(user, login_token) is True

    def test_verify_login_fails_without_secret(self, user):
        get_or_create_totp(user)
        assert verify_totp_login(user, "123456") is False

    def test_generate_secret_is_base32(self):
        secret = generate_totp_secret()
        assert len(secret) >= 16

    def test_store_pending_totp_secret(self, user):
        secret = generate_totp_secret()
        store_pending_totp_secret(user, secret)
        two_fa = get_or_create_totp(user)
        two_fa.refresh_from_db()
        assert two_fa.pending_totp_secret == secret

    def test_setup_totp_complete_rejects_overwrite(self, user, totp_secret):
        assert setup_totp_complete(user, totp_secret) is True
        assert setup_totp_complete(user, generate_totp_secret()) is False
