import logging

import pytest
from webauthn import generate_authentication_options
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, PublicKeyCredentialType

from lokdown.helpers.twofa_helper import (
    get_available_2fa_methods,
    handle_2fa_error,
    is_2fa_enabled,
    serialize_webauthn_options,
)


@pytest.mark.django_db
class TestTwoFaHelper:
    def test_is_2fa_enabled_with_totp(self, user_with_totp):
        assert is_2fa_enabled(user_with_totp) is True

    def test_is_2fa_enabled_with_passkey(self, user_with_passkey):
        assert is_2fa_enabled(user_with_passkey) is True

    def test_is_2fa_disabled_without_methods(self, user):
        assert is_2fa_enabled(user) is False

    def test_backup_codes_alone_do_not_enable_2fa(self, user):
        from lokdown.helpers.backup_codes_helper import store_backup_codes

        store_backup_codes(user, ["CODE1"])
        assert is_2fa_enabled(user) is False

    def test_get_available_methods(self, user_with_totp):
        methods = get_available_2fa_methods(user_with_totp)
        assert methods["totp"] is True
        assert methods["backup_codes"] is True

    def test_handle_2fa_error_logs_server_side_only(self, user, caplog):
        caplog.set_level(logging.ERROR)
        handle_2fa_error(ValueError("boom"), user, "Test op")
        assert "Test op failed for user testuser: boom" in caplog.text

    def test_serialize_webauthn_options_allow_credentials(self):
        cred_id = b"test-credential-id"
        options = generate_authentication_options(
            rp_id="localhost",
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=cred_id,
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                )
            ],
        )
        serialized = serialize_webauthn_options(options)
        assert "allowCredentials" in serialized
        assert len(serialized["allowCredentials"]) == 1
        assert serialized["allowCredentials"][0]["type"] == "public-key"
        assert isinstance(serialized["allowCredentials"][0]["id"], str)
