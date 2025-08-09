import secrets
from django.contrib.auth.models import User
from configuration import settings
from lokdown.models import FailedBackupCodeAttempt, BackupCodes


# Fixme do we even really need this?
def get_or_create_backup_codes(user: User) -> BackupCodes:
    """Get or create backup codes for user"""
    backup_codes, created = BackupCodes.objects.get_or_create(user=user)
    return backup_codes


def get_backup_codes(user: User) -> BackupCodes | None:
    """Get backup codes for user if they exist"""
    try:
        backup_codes = BackupCodes.objects.get(user=user)
        return backup_codes
    except BackupCodes.DoesNotExist:
        return None


def user_backup_codes_exist(user: User) -> bool:
    """Determine if user backup codes exist"""
    backup_codes = get_backup_codes(user)
    if backup_codes and len(backup_codes.codes) > 0:
        return True
    return False


def generate_backup_codes() -> list:
    """Generate backup codes for 2FA"""
    codes = []
    for _ in range(settings.BACKUP_CODES_COUNT):
        code = ''.join(
            secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(settings.BACKUP_CODE_LENGTH)
        )
        codes.append(code)
    return codes


def verify_backup_code(user: User, backup_code: str, ip_address: str = None, user_agent: str = None) -> bool:
    """Verify backup code and remove it if valid"""
    if not user_backup_codes_exist(user):
        return False

    backup_codes_obj = get_backup_codes(user)
    backup_codes = backup_codes_obj.codes

    if backup_code in backup_codes:
        backup_codes.remove(backup_code)
        backup_codes_obj.codes = backup_codes
        backup_codes_obj.save()
        return True
    else:
        # Log failed attempt
        if ip_address:
            FailedBackupCodeAttempt.objects.create(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent or '',
                attempted_code=backup_code[:3] + '***',  # Store partial for monitoring
            )
        return False


# Fixme should not create backup codes if none exist
# todo deprecate
def has_backup_codes(user: User) -> bool:
    """Check if user has backup codes"""
    backup_codes_obj = get_or_create_backup_codes(user)
    return len(backup_codes_obj.codes) > 0
