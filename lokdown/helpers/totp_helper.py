# ============================================================================
# TOTP Helper Functions
# ============================================================================

import base64
import logging
from io import BytesIO

import pyotp
import qrcode
from django.conf import settings
from django.contrib.auth.models import User

from lokdown.helpers.backup_codes_helper import generate_backup_codes, store_backup_codes
from lokdown.helpers.encryption_helper import decrypt_secret, encrypt_secret
from lokdown.models import UserTimeBasedOneTimePasswords

logger = logging.getLogger(__name__)


def get_or_create_totp(user: User) -> UserTimeBasedOneTimePasswords:
    """Get or create 2FA settings for user (only for TOTP users)"""
    two_fa, _created = UserTimeBasedOneTimePasswords.objects.get_or_create(user=user)
    return two_fa


def read_stored_secret(stored: str | None) -> str | None:
    if not stored:
        return None
    return decrypt_secret(stored)


def write_stored_secret(plaintext: str | None) -> str | None:
    if not plaintext:
        return None
    return encrypt_secret(plaintext)


def has_totp_enabled(user: User) -> bool:
    """Check if TOTP is enabled for user"""
    try:
        two_fa = UserTimeBasedOneTimePasswords.objects.get(user=user)
        return bool(two_fa.totp_secret)
    except UserTimeBasedOneTimePasswords.DoesNotExist:
        return False


def generate_totp_secret():
    """Generate a new TOTP secret"""
    return pyotp.random_base32()


def generate_totp_qr_code(secret, user):
    """Generate QR code for TOTP setup"""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.email or user.username, issuer_name=settings.WEBAUTHN_RP_NAME)

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer)
    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp_token_setup(secret, token):
    """Verify a TOTP token against a secret"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    except Exception as e:
        logger.error(f"TOTP verification error: {str(e)}")
        return False


def verify_totp_login(user: User, token: str) -> bool:
    """Verify TOTP token"""
    try:
        two_fa = UserTimeBasedOneTimePasswords.objects.get(user=user)
        secret = read_stored_secret(two_fa.totp_secret)
        if not secret:
            return False

        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    except UserTimeBasedOneTimePasswords.DoesNotExist:
        return False


def store_pending_totp_secret(user: User, secret: str) -> None:
    """Store a pending TOTP secret server-side until setup is verified."""
    two_fa = get_or_create_totp(user)
    two_fa.pending_totp_secret = write_stored_secret(secret)
    two_fa.save(update_fields=["pending_totp_secret", "updated_at"])


def setup_totp_complete(user, secret) -> tuple[bool, list[str]]:
    """Complete TOTP setup by saving secret and generating backup codes."""
    try:
        two_fa = get_or_create_totp(user)
        if two_fa.totp_secret:
            logger.warning(f"TOTP already enabled for user {user.username}")
            return False, []
        two_fa.totp_secret = write_stored_secret(secret)
        two_fa.pending_totp_secret = None
        two_fa.save(update_fields=["totp_secret", "pending_totp_secret", "updated_at"])

        plaintext_codes = generate_backup_codes()
        store_backup_codes(user, plaintext_codes)
        return True, plaintext_codes
    except Exception as e:
        logger.error(f"Failed to complete TOTP setup for user {user.username}: {str(e)}")
        return False, []
