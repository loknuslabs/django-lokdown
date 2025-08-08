# ============================================================================
# Passkey Helper Functions
# ============================================================================

import json
import uuid
import base64
import logging
from datetime import timedelta
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from webauthn import (
    verify_registration_response,
    generate_registration_options,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from lokdown.helpers.backup_codes_helper import get_or_create_backup_codes, generate_backup_codes
from lokdown.helpers.common_helper import get_client_ip
from lokdown.models import (
    PasskeyCredential,
    LoginSession,
)

logger = logging.getLogger(__name__)


def has_passkey_enabled(user: User) -> bool:
    """Check if Passkey is enabled for user"""
    return user.passkey_credentials.exists()


def generate_passkey_options(user):
    """Generate passkey registration options"""
    try:
        options = generate_registration_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            rp_name=settings.WEBAUTHN_RP_NAME,
            user_name=user.username,
            user_id=str(user.id).encode(),
            user_display_name=user.get_full_name() or user.username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED
            ),
            attestation=AttestationConveyancePreference.NONE,
        )
        return options
    except Exception as e:
        logger.error(f"Failed to generate passkey options for user {user.username}: {str(e)}")
        return None


def create_login_session_for_passkey(user, challenge, request=None):
    """Create a login session for passkey setup"""
    try:
        session_id = str(uuid.uuid4())
        challenge_base64 = base64.b64encode(challenge).decode('utf-8')

        session = LoginSession.objects.create(
            user=user,
            session_id=session_id,
            expires=timezone.now() + timedelta(minutes=settings.TWOFA_SESSION_TIMEOUT),
            challenge=challenge_base64,
        )

        if request:
            session.ip_address = get_client_ip(request)
            session.user_agent = request.META.get('HTTP_USER_AGENT')
            session.save()

        return session_id
    except Exception as e:
        logger.error(f"Failed to create login session for user {user.username}: {str(e)}")
        return None


def verify_passkey_registration(passkey_response, expected_challenge):
    """Verify passkey registration response"""
    try:
        # Parse the passkey response
        if isinstance(passkey_response, str):
            passkey_response_dict = json.loads(passkey_response)
        else:
            passkey_response_dict = passkey_response

        # Convert stored base64 challenge back to bytes
        expected_challenge_bytes = base64.b64decode(expected_challenge)

        # Verify the passkey registration response
        verification = verify_registration_response(
            credential=passkey_response_dict,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
        )

        return verification
    except json.JSONDecodeError:
        logger.error("Invalid passkey response format")
        return None
    except Exception as e:
        logger.error(f"Passkey verification failed: {str(e)}")
        return None


def save_passkey_to_database(user, verification):
    """Save passkey credential to database after successful verification"""
    try:
        # Convert public key to base64 for storage
        public_key_base64 = base64.b64encode(verification.credential_public_key).decode('utf-8')

        PasskeyCredential.objects.create(
            user=user,
            credential_id=verification.credential_id,
            public_key=public_key_base64,
            sign_count=verification.sign_count,
            rp_id=settings.WEBAUTHN_RP_ID,
            user_handle=str(user.id),
        )
        return True
    except Exception as e:
        logger.error(f"Failed to save passkey to database for user {user.username}: {str(e)}")
        return False


def setup_passkey_backup_codes(user, verification):
    """Complete passkey setup by saving credential and generating backup codes"""
    try:
        # Save passkey credential
        if not save_passkey_to_database(user, verification):
            return False

        # Generate backup codes
        backup_codes_obj = get_or_create_backup_codes(user)
        backup_codes_obj.codes = generate_backup_codes()
        backup_codes_obj.save()

        return True
    except Exception as e:
        logger.error(f"Failed to complete passkey setup for user {user.username}: {str(e)}")
        return False


def verify_passkey(user: User, response_data: dict, session_id: str) -> bool:
    """Verify passkey authentication response"""
    try:
        # Get session for challenge verification
        session = LoginSession.objects.get(session_id=session_id)
        credentials = user.passkey_credentials.all()

        if not credentials.exists():
            logger.warning(f"No passkey credentials found for user {user.id}")
            return False

        # Convert stored base64 challenge back to bytes
        expected_challenge = base64.b64decode(session.challenge)

        # Try each credential until one works
        for credential in credentials:
            try:
                # Convert stored base64 public key back to bytes
                credential_public_key = base64.b64decode(credential.public_key)

                verification = verify_authentication_response(
                    credential=response_data,
                    expected_challenge=expected_challenge,  # converted back to bytes
                    expected_rp_id=settings.WEBAUTHN_RP_ID,
                    expected_origin=settings.WEBAUTHN_ORIGIN,
                    credential_public_key=credential_public_key,  # converted back to bytes
                    credential_current_sign_count=credential.sign_count,
                )

                # Update credential sign count
                credential.sign_count = verification.new_sign_count
                credential.last_used = timezone.now()
                credential.save()

                logger.info(f"Passkey verification successful for user {user.id}")
                return True
            except Exception as e:
                logger.warning(f"Passkey verification failed for credential {credential.id}: {str(e)}")
                # Try next credential
                continue

        # If we get here, none of the credentials worked
        logger.warning(f"All passkey credentials failed for user {user.id}")
        return False
    except Exception as e:
        logger.error(f"Passkey verification error for user {user.id}: {str(e)}")
        return False


def custom_generate_authentication_options():
    """Generate passkey authentication options"""
    try:
        options = generate_authentication_options(
            rp_id=settings.WEBAUTHN_RP_ID, user_verification=UserVerificationRequirement.REQUIRED
        )
        return options
    except Exception as e:
        logger.error(f"Failed to generate authentication options: {str(e)}")
        return None
