import pytest
from django.conf import settings

from lokdown.helpers.backup_codes_helper import (
    generate_backup_codes,
    get_or_create_backup_codes,
    has_backup_codes,
    user_backup_codes_exist,
    verify_backup_code,
)
from lokdown.models import FailedBackupCodeAttempt


@pytest.mark.django_db
class TestGenerateBackupCodes:
    def test_generates_expected_count_and_length(self):
        codes = generate_backup_codes()
        assert len(codes) == settings.BACKUP_CODES_COUNT
        assert all(len(c) == settings.BACKUP_CODE_LENGTH for c in codes)
        assert len(set(codes)) == len(codes)


@pytest.mark.django_db
class TestVerifyBackupCode:
    def test_valid_code_is_consumed(self, user):
        obj = get_or_create_backup_codes(user)
        obj.codes = ["VALIDCODE1"]
        obj.save()

        assert verify_backup_code(user, "VALIDCODE1", "127.0.0.1", "pytest") is True
        obj.refresh_from_db()
        assert "VALIDCODE1" not in obj.codes

    def test_invalid_code_logs_failure(self, user):
        obj = get_or_create_backup_codes(user)
        obj.codes = ["VALIDCODE1"]
        obj.save()

        assert verify_backup_code(user, "WRONGCODE", "10.0.0.1", "agent") is False
        assert FailedBackupCodeAttempt.objects.filter(user=user).count() == 1

    def test_no_codes_returns_false_without_creating_row(self, user):
        assert user_backup_codes_exist(user) is False
        assert verify_backup_code(user, "ANYCODE") is False
        assert has_backup_codes(user) is False

    def test_has_backup_codes_read_only(self, user):
        assert has_backup_codes(user) is False
        backup = get_or_create_backup_codes(user)
        backup.codes = ["CODEAAAA"]
        backup.save(update_fields=["codes"])
        assert has_backup_codes(user) is True
