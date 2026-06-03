import pyotp
import pytest

from lokdown.helpers.totp_helper import (
    generate_totp_secret,
    get_or_create_totp,
    has_totp_enabled,
    read_stored_secret,
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
        ok, backup_codes = setup_totp_complete(user, totp_secret)
        assert ok is True
        assert len(backup_codes) == 4
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
        assert read_stored_secret(two_fa.pending_totp_secret) == secret

    def test_setup_totp_complete_rejects_overwrite(self, user, totp_secret):
        ok, _ = setup_totp_complete(user, totp_secret)
        assert ok is True
        ok, _ = setup_totp_complete(user, generate_totp_secret())
        assert ok is False

    def test_totp_secret_stored_encrypted(self, user, totp_secret):
        setup_totp_complete(user, totp_secret)
        two_fa = get_or_create_totp(user)
        two_fa.refresh_from_db()
        assert two_fa.totp_secret != totp_secret
        assert read_stored_secret(two_fa.totp_secret) == totp_secret
