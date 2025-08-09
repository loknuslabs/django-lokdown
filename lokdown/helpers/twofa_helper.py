import base64
import logging
from django.contrib.auth.models import User
from lokdown.helpers.passkey_helper import has_passkey_enabled
from lokdown.helpers.totp_helper import has_totp_enabled
from lokdown.models import (
    UserTimeBasedOneTimePasswords,
    BackupCodes,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Utility Helper Functions
# ============================================================================


def is_2fa_enabled(user: User) -> bool:
    """Check if 2FA is enabled for user (either TOTP or Passkey)"""
    has_totp = has_totp_enabled(user)
    has_passkey = has_passkey_enabled(user)
    return has_totp or has_passkey


def get_available_2fa_methods(user: User) -> dict:
    """Get available 2FA methods for user without creating them if they don't exist"""
    methods = {'totp': False, 'passkey': False, 'backup_codes': False}

    # Check TOTP without creating
    try:
        two_fa = UserTimeBasedOneTimePasswords.objects.get(user=user)
        methods['totp'] = bool(two_fa.totp_secret)
    except UserTimeBasedOneTimePasswords.DoesNotExist:
        methods['totp'] = False

    # Check Passkey
    methods['passkey'] = user.passkey_credentials.exists()

    # Check Backup Codes without creating
    try:
        backup_codes_obj = BackupCodes.objects.get(user=user)
        methods['backup_codes'] = len(backup_codes_obj.codes) > 0
    except BackupCodes.DoesNotExist:
        methods['backup_codes'] = False

    return methods


# ============================================================================
# Serialization Helper Functions
# ============================================================================


def serialize_webauthn_options(options, visited=None):
    """Serialize WebAuthn options to JSON-compatible dict with camelCase keys"""
    if visited is None:
        visited = set()

    # Prevent circular references
    obj_id = id(options)
    if obj_id in visited:
        return str(options)
    visited.add(obj_id)

    # Field name mapping from snake_case to camelCase
    field_mapping = {
        'pub_key_cred_params': 'pubKeyCredParams',
        'authenticator_selection': 'authenticatorSelection',
        'user_verification': 'userVerification',
        'resident_key': 'residentKey',
        'attestation_conveyance': 'attestationConveyance',
        'exclude_credentials': 'excludeCredentials',
        'supported_pub_key_algs': 'supportedPubKeyAlgs',
        'display_name': 'displayName',
    }

    result = {}
    for key, value in options.__dict__.items():
        try:
            # Convert snake_case to camelCase
            camel_key = field_mapping.get(key, key)

            if hasattr(value, '__dict__') and not isinstance(value, (str, int, float, bool)):
                # Handle nested objects
                result[camel_key] = serialize_webauthn_options(value, visited)
            elif isinstance(value, bytes):
                # Convert bytes to base64
                result[camel_key] = base64.b64encode(value).decode('utf-8')
            elif key == 'challenge':
                # Special handling for challenge
                result[camel_key] = base64.b64encode(value).decode('utf-8')
            elif key == 'user':
                # Special handling for user object
                result[camel_key] = {
                    'id': base64.b64encode(value.id).decode('utf-8'),
                    'name': value.name,
                    'displayName': value.display_name,
                }
            elif key == 'rp':
                # Special handling for rp object
                result[camel_key] = {'name': value.name, 'id': value.id}
            elif key == 'pub_key_cred_params':
                # Special handling for pub key cred params
                result[camel_key] = [{'alg': param.alg, 'type': param.type} for param in value]
            elif key == 'authenticator_selection':
                # Special handling for authenticator selection
                result[camel_key] = {
                    'residentKey': value.resident_key.value,
                    'userVerification': value.user_verification.value,
                }
            elif key == 'attestation':
                # Special handling for attestation
                result[camel_key] = value.value
            elif hasattr(value, 'value'):  # Handle enum-like objects
                result[camel_key] = value.value
            else:
                result[camel_key] = value
        except Exception as e:
            logger.warning(f"Failed to serialize field {key}: {str(e)}")
            result[camel_key] = str(value)

    return result


# ============================================================================
# Error Handling Helper Functions
# ============================================================================


def handle_2fa_error(error, user=None, operation="2FA operation"):
    """Centralized error handling for 2FA operations"""
    error_msg = f"{operation} failed: {str(error)}"
    if user:
        logger.error(f"{error_msg} for user {user.username}")
    else:
        logger.error(error_msg)
    return error_msg
