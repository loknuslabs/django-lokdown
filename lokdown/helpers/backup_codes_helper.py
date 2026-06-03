import secrets

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.conf import settings

from lokdown.models import BackupCodes, FailedBackupCodeAttempt


def get_or_create_backup_codes(user: User) -> BackupCodes:
    """Get or create backup codes for user"""
    backup_codes, _created = BackupCodes.objects.get_or_create(user=user)
    return backup_codes


def get_backup_codes(user: User) -> BackupCodes | None:
    """Get backup codes for user if they exist"""
    try:
        return BackupCodes.objects.get(user=user)
    except BackupCodes.DoesNotExist:
        return None


def is_hashed_backup_code(value: str) -> bool:
    return isinstance(value, str) and value.count("$") >= 2 and not value.startswith("$")


def hash_backup_code(code: str) -> str:
    return make_password(code.upper())


def store_backup_codes(user: User, plaintext_codes: list[str]) -> list[str]:
    """Persist hashed backup codes and return plaintext for one-time display."""
    backup_codes_obj = get_or_create_backup_codes(user)
    backup_codes_obj.codes = [hash_backup_code(code) for code in plaintext_codes]
    backup_codes_obj.save(update_fields=["codes", "updated_at"])
    return plaintext_codes


def user_backup_codes_exist(user: User) -> bool:
    """Determine if user backup codes exist"""
    backup_codes = get_backup_codes(user)
    return bool(backup_codes and len(backup_codes.codes) > 0)


def generate_backup_codes() -> list[str]:
    """Generate backup codes for 2FA"""
    codes = []
    for _ in range(settings.BACKUP_CODES_COUNT):
        code = "".join(
            secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(settings.BACKUP_CODE_LENGTH)
        )
        codes.append(code)
    return codes


def _matches_backup_code(attempt: str, stored: str) -> bool:
    normalized = attempt.upper()
    if is_hashed_backup_code(stored):
        return check_password(normalized, stored)
    return secrets.compare_digest(normalized, stored.upper())


def verify_backup_code(user: User, backup_code: str, ip_address: str = None, user_agent: str = None) -> bool:
    """Verify backup code and remove it if valid"""
    if not user_backup_codes_exist(user):
        return False

    backup_codes_obj = get_backup_codes(user)
    stored_codes = list(backup_codes_obj.codes or [])

    for index, stored in enumerate(stored_codes):
        if _matches_backup_code(backup_code, stored):
            stored_codes.pop(index)
            backup_codes_obj.codes = stored_codes
            backup_codes_obj.save(update_fields=["codes", "updated_at"])
            return True

    if ip_address:
        FailedBackupCodeAttempt.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent or "",
            attempted_code=backup_code[:3] + "***",
        )
    return False


def has_backup_codes(user: User) -> bool:
    """Check if user has backup codes (read-only; no row creation)."""
    return user_backup_codes_exist(user)
