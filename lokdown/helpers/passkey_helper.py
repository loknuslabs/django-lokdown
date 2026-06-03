# ============================================================================
# Passkey Helper Functions
# ============================================================================

import ast
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
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from lokdown.helpers.common_helper import get_client_ip
from lokdown.helpers.webauthn_settings_helper import (
    get_webauthn_expected_origin,
    resolve_rp_id,
)
from lokdown.models import (
    PasskeyCredential,
    LoginSession,
)

logger = logging.getLogger(__name__)


def repair_base64_form_value(value: str) -> str:
    """
    Repair base64 fields corrupted by application/x-www-form-urlencoded (``+`` → space).

    Admin HTML forms POST passkey JSON in a hidden field; API clients send JSON bodies and
    do not hit this issue.
    """
    if " " in value and "+" not in value:
        return value.replace(" ", "+")
    return value


def normalize_passkey_credential_response(passkey_response: dict | str) -> dict:
    """
    Normalize browser/WebAuthn JSON for py_webauthn (requires rawId, type, camelCase response keys).
    """
    if isinstance(passkey_response, str):
        passkey_response = json.loads(passkey_response)
    if not isinstance(passkey_response, dict):
        raise TypeError("passkey_response must be a JSON object")

    normalized = dict(passkey_response)
    if not normalized.get("rawId") and normalized.get("id"):
        normalized["rawId"] = normalized["id"]
    if not normalized.get("type"):
        normalized["type"] = "public-key"

    if isinstance(normalized.get("rawId"), str):
        normalized["rawId"] = repair_base64_form_value(normalized["rawId"])

    response = normalized.get("response")
    if isinstance(response, dict):
        response = dict(response)
        for snake, camel in (
            ("client_data_json", "clientDataJSON"),
            ("authenticator_data", "authenticatorData"),
        ):
            if camel not in response and snake in response:
                response[camel] = response.pop(snake)
        for field in (
            "clientDataJSON",
            "authenticatorData",
            "signature",
            "attestationObject",
            "userHandle",
        ):
            if isinstance(response.get(field), str):
                response[field] = repair_base64_form_value(response[field])
        normalized["response"] = response

    return normalized


def decode_stored_credential_id(credential_id: str) -> bytes:
    """Decode credential id from DB (base64url or legacy str(bytes) values)."""
    if credential_id.startswith(("b'", 'b"')):
        return ast.literal_eval(credential_id)
    return base64url_to_bytes(credential_id)


def build_allow_credentials(
    user: User,
    expected_rp_id: str | None = None,
) -> list[PublicKeyCredentialDescriptor]:
    """Build allowCredentials for authentication from stored passkeys."""
    descriptors = []
    for credential in user.passkey_credentials.all():
        if expected_rp_id and credential.rp_id != expected_rp_id:
            continue
        try:
            descriptors.append(
                PublicKeyCredentialDescriptor(
                    id=decode_stored_credential_id(credential.credential_id),
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                )
            )
        except Exception as e:
            logger.warning(
                "Skipping passkey credential %s for user %s: %s",
                credential.id,
                user.id,
                e,
            )
    return descriptors


def has_passkey_enabled(user: User) -> bool:
    """Check if Passkey is enabled for user"""
    return user.passkey_credentials.exists()


def generate_passkey_options(user, request=None):
    """Generate passkey registration options"""
    try:
        options = generate_registration_options(
            rp_id=resolve_rp_id(request),
            rp_name=settings.WEBAUTHN_RP_NAME,
            user_name=user.username,
            user_id=str(user.id).encode(),
            user_display_name=user.get_full_name() or user.username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
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
        challenge_base64 = base64.b64encode(challenge).decode("utf-8")

        session = LoginSession.objects.create(
            user=user,
            session_id=session_id,
            requires_2fa=True,
            expires_at=timezone.now() + timedelta(minutes=settings.TWOFA_SESSION_TIMEOUT),
            challenge=challenge_base64,
        )

        if request:
            session.ip_address = get_client_ip(request)
            session.user_agent = request.META.get("HTTP_USER_AGENT", "")
            session.save(update_fields=["ip_address", "user_agent"])

        return session_id
    except Exception as e:
        logger.error(f"Failed to create login session for user {user.username}: {str(e)}")
        return None


def verify_passkey_registration(passkey_response, expected_challenge, request=None):
    """Verify passkey registration response"""
    try:
        passkey_response_dict = normalize_passkey_credential_response(passkey_response)

        # Convert stored base64 challenge back to bytes
        expected_challenge_bytes = base64.b64decode(expected_challenge)

        # Verify the passkey registration response
        verification = verify_registration_response(
            credential=passkey_response_dict,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=resolve_rp_id(request),
            expected_origin=get_webauthn_expected_origin(),
        )

        return verification
    except json.JSONDecodeError:
        logger.error("Invalid passkey response format")
        return None
    except Exception as e:
        logger.error(f"Passkey verification failed: {str(e)}")
        return None


def save_passkey_to_database(user, verification, request=None):
    """Save passkey credential to database after successful verification"""
    try:
        # Convert public key to base64 for storage
        public_key_base64 = base64.b64encode(verification.credential_public_key).decode("utf-8")

        PasskeyCredential.objects.create(
            user=user,
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=public_key_base64,
            sign_count=verification.sign_count,
            rp_id=resolve_rp_id(request),
            user_handle=str(user.id),
        )
        return True
    except Exception as e:
        logger.error(f"Failed to save passkey to database for user {user.username}: {str(e)}")
        return False


def verify_passkey(user: User, response_data: dict | str, session_id: str, request=None) -> bool:
    """Verify passkey authentication response"""
    try:
        response_data = normalize_passkey_credential_response(response_data)
        session = LoginSession.objects.get(
            session_id=session_id,
            expires_at__gt=timezone.now(),
        )
        if session.user_id != user.id:
            logger.warning(
                "Passkey verification session user mismatch: session %s user %s, expected user %s",
                session_id,
                session.user_id,
                user.id,
            )
            return False
        if not session.challenge:
            logger.warning("Passkey verification attempted without challenge on session %s", session_id)
            return False
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
                    expected_challenge=expected_challenge,
                    expected_rp_id=credential.rp_id,
                    expected_origin=get_webauthn_expected_origin(),
                    credential_public_key=credential_public_key,
                    credential_current_sign_count=credential.sign_count,
                    require_user_verification=True,
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


def custom_generate_authentication_options(user: User, request=None):
    """Generate passkey authentication options scoped to the user's registered credentials."""
    try:
        rp_id = resolve_rp_id(request)
        allow_credentials = build_allow_credentials(user, expected_rp_id=rp_id)
        options = generate_authentication_options(
            rp_id=rp_id,
            user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=allow_credentials or None,
        )
        return options
    except Exception as e:
        logger.error(f"Failed to generate authentication options: {str(e)}")
        return None
