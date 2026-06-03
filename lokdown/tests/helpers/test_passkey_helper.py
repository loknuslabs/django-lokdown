import base64
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from lokdown.helpers.passkey_helper import (
    create_login_session_for_passkey,
    has_passkey_enabled,
    save_passkey_to_database,
)
from lokdown.models import LoginSession, PasskeyCredential


@pytest.mark.django_db
class TestPasskeyHelper:
    def test_has_passkey_enabled(self, user, user_with_passkey, other_user):
        assert has_passkey_enabled(other_user) is False
        assert has_passkey_enabled(user_with_passkey) is True

    def test_create_login_session_for_passkey(self, user):
        challenge = b"test-challenge-bytes-12345"
        session_id = create_login_session_for_passkey(user, challenge)
        session = LoginSession.objects.get(session_id=session_id)
        assert session.challenge == base64.b64encode(challenge).decode("utf-8")
        assert session.expires_at > timezone.now()

    def test_save_passkey_to_database(self, user):
        verification = MagicMock()
        verification.credential_public_key = b"public-key-bytes"
        verification.credential_id = "cred-123"
        verification.sign_count = 1

        assert save_passkey_to_database(user, verification) is True
        assert PasskeyCredential.objects.filter(user=user, credential_id="cred-123").exists()

    @patch("lokdown.helpers.passkey_helper.generate_registration_options")
    def test_generate_passkey_options_success(self, mock_gen, user):
        mock_gen.return_value = MagicMock(challenge=b"abc")
        from lokdown.helpers.passkey_helper import generate_passkey_options

        result = generate_passkey_options(user)
        assert result is not None
        mock_gen.assert_called_once()
