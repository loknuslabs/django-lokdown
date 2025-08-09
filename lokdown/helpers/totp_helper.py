# ============================================================================
# TOTP Helper Functions
# ============================================================================

import base64
import pyotp
import qrcode
import logging
from io import BytesIO
from django.conf import settings
from django.contrib.auth.models import User
from lokdown.helpers.backup_codes_helper import generate_backup_codes, get_or_create_backup_codes
from lokdown.models import UserTimeBasedOneTimePasswords

logger = logging.getLogger(__name__)


def get_or_create_2fa(user: User) -> UserTimeBasedOneTimePasswords:
    """Get or create 2FA settings for user (only for TOTP users)"""
    two_fa, created = UserTimeBasedOneTimePasswords.objects.get_or_create(user=user)
    return two_fa


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

    # Convert to base64
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
        if not two_fa.totp_secret:
            return False

        totp = pyotp.TOTP(two_fa.totp_secret)
        return totp.verify(token)
    except UserTimeBasedOneTimePasswords.DoesNotExist:
        return False


def save_totp_to_database(user, secret):
    """Save TOTP secret to database after successful verification"""
    try:
        two_fa = get_or_create_2fa(user)
        two_fa.totp_secret = secret
        two_fa.save()
        return True
    except Exception as e:
        logger.error(f"Failed to save TOTP to database for user {user.username}: {str(e)}")
        return False


def setup_totp_complete(user, secret):
    """Complete TOTP setup by saving secret and generating backup codes"""
    try:
        # Save TOTP secret
        if not save_totp_to_database(user, secret):
            return False

        # Generate backup codes
        backup_codes_obj = get_or_create_backup_codes(user)
        backup_codes_obj.codes = generate_backup_codes()
        backup_codes_obj.save()

        return True
    except Exception as e:
        logger.error(f"Failed to complete TOTP setup for user {user.username}: {str(e)}")
        return False
