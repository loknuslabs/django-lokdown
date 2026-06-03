from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.utils import timezone

from lokdown.models import FailedBackupCodeAttempt, LoginSession, PasskeyCredential


@pytest.mark.django_db
class TestSecurityAuditCommand:
    def test_cleanup_dry_run_does_not_delete(self, user):
        LoginSession.objects.create(
            user=user,
            session_id="expired-session",
            expires_at=timezone.now() - timedelta(minutes=5),
        )
        PasskeyCredential.objects.create(
            user=user,
            credential_id="old-passkey",
            public_key="dGVzdA==",
            sign_count=0,
            rp_id="localhost",
            user_handle=str(user.id),
            last_used=timezone.now() - timedelta(days=120),
        )
        FailedBackupCodeAttempt.objects.create(
            user=user,
            ip_address="127.0.0.1",
        )
        FailedBackupCodeAttempt.objects.filter(user=user).update(
            created_at=timezone.now() - timedelta(days=45),
        )

        out = StringIO()
        call_command("security_audit", "--cleanup", stdout=out)
        output = out.getvalue()

        assert "Dry run" in output
        assert "Would delete 1 expired sessions" in output
        assert "Would delete 1 old failed attempts" in output
        assert "Would delete 1 old passkeys" in output
        assert LoginSession.objects.filter(session_id="expired-session").exists()
        assert PasskeyCredential.objects.filter(credential_id="old-passkey").exists()
        assert FailedBackupCodeAttempt.objects.filter(user=user).count() == 1

    def test_cleanup_force_deletes_records(self, user):
        LoginSession.objects.create(
            user=user,
            session_id="expired-session-force",
            expires_at=timezone.now() - timedelta(minutes=5),
        )
        PasskeyCredential.objects.create(
            user=user,
            credential_id="old-passkey-force",
            public_key="dGVzdA==",
            sign_count=0,
            rp_id="localhost",
            user_handle=str(user.id),
            last_used=timezone.now() - timedelta(days=120),
        )
        FailedBackupCodeAttempt.objects.create(
            user=user,
            ip_address="127.0.0.1",
        )
        FailedBackupCodeAttempt.objects.filter(user=user).update(
            created_at=timezone.now() - timedelta(days=45),
        )

        out = StringIO()
        call_command("security_audit", "--cleanup", "--force", stdout=out)
        output = out.getvalue()

        assert "Dry run" not in output
        assert "Deleted 1 expired sessions" in output
        assert "Deleted 1 old failed attempts" in output
        assert "Deleted 1 old passkeys" in output
        assert not LoginSession.objects.filter(session_id="expired-session-force").exists()
        assert not PasskeyCredential.objects.filter(credential_id="old-passkey-force").exists()
        assert FailedBackupCodeAttempt.objects.filter(user=user).count() == 0

    def test_force_without_cleanup_warns(self):
        err = StringIO()
        call_command("security_audit", "--force", stderr=err)
        assert "--force has no effect without --cleanup" in err.getvalue()
