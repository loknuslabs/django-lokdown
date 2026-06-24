"""
Centralized authentication and 2FA business logic for API and admin flows.
"""

from __future__ import annotations

import base64
import logging
import uuid
from datetime import timedelta
from typing import Any, Literal

import pyotp
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from django_ratelimit.core import is_ratelimited
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from lokdown.helpers.backup_codes_helper import (
    generate_backup_codes,
    get_or_create_backup_codes,
    store_backup_codes,
    user_backup_codes_exist,
    verify_backup_code,
)
from lokdown.helpers.common_helper import get_client_ip
from lokdown.helpers.rate_limit_helper import check_totp_verify_rate_limit
from lokdown.helpers.passkey_helper import (
    create_login_session_for_passkey,
    custom_generate_authentication_options,
    generate_passkey_options,
    has_passkey_enabled,
    save_passkey_to_database,
    verify_passkey,
    verify_passkey_registration,
)
from lokdown.helpers.totp_helper import (
    generate_totp_qr_code,
    generate_totp_secret,
    get_or_create_totp,
    has_totp_enabled,
    read_stored_secret,
    setup_totp_complete,
    store_pending_totp_secret,
    verify_totp_login,
    verify_totp_token_setup,
)
from lokdown.helpers.feature_settings_helper import admin_2fa_required, passkey_enabled, totp_enabled
from lokdown.helpers.twofa_helper import is_2fa_enabled, serialize_webauthn_options
from lokdown.models import LoginSession, UserTimeBasedOneTimePasswords

logger = logging.getLogger(__name__)

TokenKeyStyle = Literal["rest", "simplejwt"]


def create_authentication_session(user, request=None) -> str | None:
    """Create a LoginSession for pending 2FA verification."""
    try:
        session_id = str(uuid.uuid4())
        session = LoginSession.objects.create(
            user=user,
            session_id=session_id,
            requires_2fa=True,
            expires_at=timezone.now() + timedelta(minutes=settings.TWOFA_SESSION_TIMEOUT),
        )
        if request:
            session.ip_address = get_client_ip(request)
            session.user_agent = request.META.get("HTTP_USER_AGENT", "")
            session.save(update_fields=["ip_address", "user_agent"])
        return session_id
    except Exception as e:
        logger.error("Failed to create authentication session for %s: %s", user.username, e)
        return None


def validate_session_data(
    session_id: str | None,
    request=None,
) -> tuple[LoginSession | None, str | None]:
    if not session_id:
        return None, "No session ID provided"
    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
    except LoginSession.DoesNotExist:
        return None, "Invalid or expired session"

    return session, None


def require_self_user(request_user: User, user_id: int) -> User | Response:
    """Ensure the authenticated user can only act on their own account."""
    if request_user.id != user_id:
        return Response({"error": "Not authorized for this user"}, status=status.HTTP_403_FORBIDDEN)
    return request_user


def staff_must_setup_2fa(user: User) -> bool:
    """Staff with ADMIN_2FA_REQUIRED who have not enrolled a primary 2FA method yet."""
    return admin_2fa_required() and user.is_staff and not is_2fa_enabled(user)


def login_requires_2fa_step(user: User) -> bool:
    """True when password/OAuth login must continue with verify or enrollment."""
    return is_2fa_enabled(user) or staff_must_setup_2fa(user)


def build_pre_2fa_payload(user: User, session_id: str) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "requires_2fa": True,
        "requires_2fa_setup": False,
        "totp_enabled": totp_enabled() and has_totp_enabled(user),
        "passkey_enabled": passkey_enabled() and has_passkey_enabled(user),
        "backup_codes_available": user_backup_codes_exist(user),
    }


def build_pre_2fa_setup_payload(user: User, session_id: str) -> dict[str, Any]:
    """Pending login session for staff who must enroll 2FA before receiving JWTs."""
    return {
        "session_id": session_id,
        "requires_2fa": True,
        "requires_2fa_setup": True,
        "totp_enabled": False,
        "passkey_enabled": False,
        "backup_codes_available": False,
        "totp_available": totp_enabled(),
        "passkey_available": passkey_enabled(),
    }


def build_jwt_token_payload(user: User, *, key_style: TokenKeyStyle = "rest") -> dict[str, Any]:
    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)
    refresh_token = str(refresh)
    if key_style == "simplejwt":
        return {"access": access, "refresh": refresh_token, "requires_2fa": False}
    return {
        "access_token": access,
        "refresh_token": refresh_token,
        "requires_2fa": False,
    }


def validate_staff_2fa_setup_user(user: User) -> Response | None:
    """Ensure a user may enroll 2FA during a pending staff login."""
    if not user.is_staff:
        return Response({"error": "Not authorized for this user"}, status=status.HTTP_403_FORBIDDEN)
    if not admin_2fa_required():
        return Response({"error": "Admin 2FA is not required"}, status=status.HTTP_400_BAD_REQUEST)
    if is_2fa_enabled(user):
        return Response(
            {"error": "2FA is already enabled; complete verification instead"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return None


def validate_staff_2fa_setup_session(session: LoginSession) -> Response | None:
    """Ensure a pending LoginSession is valid for staff first-time 2FA enrollment."""
    if session.is_authenticated:
        return Response({"error": "Session already used"}, status=status.HTTP_400_BAD_REQUEST)
    return validate_staff_2fa_setup_user(session.user)


def initiate_password_login(user: User, request) -> dict[str, Any]:
    """After valid password auth: return either JWT payload or pre-2FA session payload."""
    if not login_requires_2fa_step(user):
        return build_jwt_token_payload(user)

    session_id = create_authentication_session(user, request)
    if not session_id:
        raise RuntimeError("Failed to create authentication session")
    if staff_must_setup_2fa(user):
        return build_pre_2fa_setup_payload(user, session_id)
    return build_pre_2fa_payload(user, session_id)


def complete_staff_login_totp_setup(
    session: LoginSession,
    totp_token: str,
    request,
    *,
    key_style: TokenKeyStyle = "rest",
) -> dict[str, Any] | Response:
    """Complete TOTP enrollment during staff first login and issue JWTs."""
    error_response = validate_staff_2fa_setup_session(session)
    if error_response:
        return error_response
    if not totp_enabled():
        return Response(
            {"error": "TOTP support is disabled"},
            status=status.HTTP_403_FORBIDDEN,
        )

    ok, error, backup_codes = complete_totp_setup(session.user, totp_token)
    if not ok:
        code: int = status.HTTP_401_UNAUTHORIZED if error == "Invalid TOTP token" else status.HTTP_400_BAD_REQUEST
        if error == "Failed to complete TOTP setup":
            code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return Response({"error": error}, status=code)

    payload = complete_login_with_tokens(
        session,
        request,
        key_style=key_style,
        message="TOTP setup verified successfully",
    )
    payload["backup_codes"] = backup_codes
    return payload


def complete_staff_login_passkey_setup(
    session: LoginSession,
    passkey_response: dict | str,
    request,
    *,
    key_style: TokenKeyStyle = "rest",
) -> dict[str, Any] | Response:
    """Complete passkey enrollment during staff first login and issue JWTs."""
    if session.is_authenticated:
        return Response({"error": "Session already used"}, status=status.HTTP_400_BAD_REQUEST)

    error_response = validate_staff_2fa_setup_user(session.user)
    if error_response:
        return error_response
    if not passkey_enabled():
        return Response(
            {"error": "Passkey support is disabled"},
            status=status.HTTP_403_FORBIDDEN,
        )

    ok, error, backup_codes = complete_passkey_registration(
        session.user,
        session.session_id,
        passkey_response,
        create_backup_codes_if_missing=True,
        request=request,
    )
    if not ok:
        code: int = status.HTTP_401_UNAUTHORIZED if error == "Invalid passkey response" else status.HTTP_400_BAD_REQUEST
        if error == "Failed to save passkey credential":
            code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return Response({"error": error}, status=code)

    payload = complete_login_with_tokens(
        session,
        request,
        key_style=key_style,
        message="Passkey setup verified successfully",
    )
    payload["backup_codes"] = backup_codes
    return payload


def _mark_session_verified(session: LoginSession, method: str) -> None:
    if method == "totp":
        session.totp_verified = True
    elif method == "passkey":
        session.passkey_verified = True
    session.save(update_fields=["totp_verified", "passkey_verified"])


def check_backup_rate_limit(request) -> Response | None:
    if is_ratelimited(
        request,
        group="backup_code",
        key="ip",
        rate=f"{settings.BACKUP_CODE_RATE_LIMIT}/m",
        method="POST",
        increment=True,
    ):
        return Response(
            {"error": "Too many backup code attempts"},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )
    return None


def verify_second_factor(
    session_id: str,
    totp_token: str | None,
    passkey_response: dict | None,
    backup_code: str | None,
    request,
) -> LoginSession | Response:
    """Verify TOTP, passkey, or backup code for a pending login session."""
    session, error = validate_session_data(session_id)
    if not session:
        return Response({"error": error or "Invalid or expired session"}, status=status.HTTP_400_BAD_REQUEST)

    if session.is_authenticated:
        return Response({"error": "Session already used"}, status=status.HTTP_400_BAD_REQUEST)

    totp_token = (totp_token or "").strip() or None
    backup_code = (backup_code or "").strip() or None

    if totp_token and has_totp_enabled(session.user):
        rate_limit_response = check_totp_verify_rate_limit(request, session.user.username)
        if rate_limit_response:
            return rate_limit_response
        if verify_totp_login(session.user, totp_token):
            _mark_session_verified(session, "totp")
            return session
        return Response({"error": "Invalid TOTP token"}, status=status.HTTP_401_UNAUTHORIZED)

    if passkey_response and has_passkey_enabled(session.user):
        if verify_passkey(session.user, passkey_response, session_id, request):
            _mark_session_verified(session, "passkey")
            return session
        return Response({"error": "Invalid passkey response"}, status=status.HTTP_401_UNAUTHORIZED)

    if backup_code:
        rate_limit_response = check_backup_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response
        if verify_backup_code(
            session.user,
            backup_code,
            get_client_ip(request),
            request.META.get("HTTP_USER_AGENT", ""),
        ):
            return session
        return Response({"error": "Invalid backup code"}, status=status.HTTP_401_UNAUTHORIZED)

    return Response({"error": "No valid 2FA method provided"}, status=status.HTTP_400_BAD_REQUEST)


def complete_login_with_tokens(
    session: LoginSession,
    request,
    *,
    key_style: TokenKeyStyle = "rest",
    message: str | None = None,
) -> dict[str, Any]:
    session.is_authenticated = True
    session.save(update_fields=["is_authenticated"])
    payload = build_jwt_token_payload(session.user, key_style=key_style)
    if message:
        payload["message"] = message
    return payload


def begin_totp_setup(user: User) -> dict[str, Any]:
    if not totp_enabled():
        raise ValueError("TOTP support is disabled")
    secret = generate_totp_secret()
    store_pending_totp_secret(user, secret)
    qr_base64 = generate_totp_qr_code(secret, user)
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email or user.username,
        issuer_name=settings.WEBAUTHN_RP_NAME,
    )
    return {
        "secret": secret,
        "qr_code": qr_base64,
        "provisioning_uri": provisioning_uri,
    }


def complete_totp_setup(user: User, totp_token: str) -> tuple[bool, str | None, list[str]]:
    if not totp_enabled():
        return False, "TOTP support is disabled", []
    if not totp_token:
        return False, "Missing token", []
    if has_totp_enabled(user):
        return False, "TOTP is already enabled", []
    two_fa = get_or_create_totp(user)
    secret = read_stored_secret(two_fa.pending_totp_secret)
    if not secret:
        return False, "No pending TOTP setup found", []
    if not verify_totp_token_setup(secret, totp_token):
        return False, "Invalid TOTP token", []
    ok, backup_codes = setup_totp_complete(user, secret)
    if not ok:
        return False, "Failed to complete TOTP setup", []
    return True, None, backup_codes


def begin_passkey_registration(user: User, request) -> dict[str, Any] | Response:
    if not passkey_enabled():
        return Response(
            {"error": "Passkey support is disabled"},
            status=status.HTTP_403_FORBIDDEN,
        )
    options = generate_passkey_options(user, request)
    if not options:
        return Response(
            {"error": "Failed to generate passkey options"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    session_id = create_login_session_for_passkey(user, options.challenge, request)
    if not session_id:
        return Response(
            {"error": "Failed to create login session"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return {
        "session_id": session_id,
        "options": serialize_webauthn_options(options),
    }


def complete_passkey_registration(
    user: User,
    session_id: str,
    passkey_response: dict | str,
    *,
    create_backup_codes_if_missing: bool = True,
    request=None,
) -> tuple[bool, str | None, list[str]]:
    if not passkey_enabled():
        return False, "Passkey support is disabled", []
    try:
        session = LoginSession.objects.get(
            session_id=session_id,
            user=user,
            expires_at__gt=timezone.now(),
        )
    except LoginSession.DoesNotExist:
        return False, "Invalid or expired session", []

    if not session.challenge:
        return False, "No valid session challenge found", []

    verification = verify_passkey_registration(passkey_response, session.challenge, request)
    if not verification:
        return False, "Invalid passkey response", []

    if not save_passkey_to_database(user, verification, request):
        return False, "Failed to save passkey credential", []

    backup_codes: list[str] = []
    if create_backup_codes_if_missing:
        backup_codes = store_backup_codes(user, generate_backup_codes())

    return True, None, backup_codes


def validate_login_session(session_id: str | None) -> LoginSession | Response:
    """Return a valid pending LoginSession or a DRF error response."""
    session, error = validate_session_data(session_id)
    if not session:
        return Response({"error": error or "Invalid or expired session"}, status=status.HTTP_400_BAD_REQUEST)
    return session


def begin_passkey_authentication(session: LoginSession, request=None) -> dict[str, Any] | Response:
    if not has_passkey_enabled(session.user):
        return Response(
            {"error": "User does not have passkey enabled"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    options = custom_generate_authentication_options(session.user, request)
    if not options:
        return Response(
            {"error": "Failed to generate authentication options"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    challenge_base64 = base64.b64encode(options.challenge).decode("utf-8")
    session.challenge = challenge_base64
    session.save(update_fields=["challenge"])

    return {
        "challenge": challenge_base64,
        "rp_id": options.rp_id,
        "timeout": options.timeout,
        "options": serialize_webauthn_options(options),
    }


def disable_user_2fa(user: User) -> None:
    """Remove all 2FA methods and backup codes for a user."""
    try:
        two_fa = UserTimeBasedOneTimePasswords.objects.get(user=user)
    except UserTimeBasedOneTimePasswords.DoesNotExist:
        two_fa = None
    if two_fa and (two_fa.totp_secret or two_fa.pending_totp_secret):
        two_fa.totp_secret = None
        two_fa.pending_totp_secret = None
        two_fa.save(update_fields=["totp_secret", "pending_totp_secret", "updated_at"])

    user.passkey_credentials.all().delete()

    backup_codes_obj = get_or_create_backup_codes(user)
    backup_codes_obj.codes = []
    backup_codes_obj.save(update_fields=["codes", "updated_at"])


def verify_admin_second_factor(
    session: LoginSession,
    totp_token: str | None,
    passkey_response: dict | str | None,
    backup_code: str | None,
    request,
) -> tuple[bool, str | None]:
    """Verify 2FA for admin HTML flow. Returns (success, error_message)."""
    import json

    if session.is_authenticated:
        return False, "Session already used"

    totp_token = (totp_token or "").strip() or None
    backup_code = (backup_code or "").strip() or None

    if totp_token and has_totp_enabled(session.user):
        if verify_totp_login(session.user, totp_token):
            _mark_session_verified(session, "totp")
            return True, None
        return False, "Invalid TOTP token"

    if passkey_response and has_passkey_enabled(session.user):
        if isinstance(passkey_response, str):
            passkey_response = json.loads(passkey_response)
        if verify_passkey(session.user, passkey_response, session.session_id, request):
            _mark_session_verified(session, "passkey")
            return True, None
        return False, "Invalid passkey response"

    if backup_code:
        rate_limit_response = check_backup_rate_limit(request)
        if rate_limit_response:
            return False, "Too many backup code attempts"
        if verify_backup_code(
            session.user,
            backup_code,
            get_client_ip(request),
            request.META.get("HTTP_USER_AGENT", ""),
        ):
            return True, None
        return False, "Invalid backup code"

    return False, "Invalid 2FA token"


def admin_passkey_auth_options_payload(session: LoginSession, request=None) -> dict[str, Any] | Response:
    """Challenge payload for admin passkey verify template (no nested options)."""
    result = begin_passkey_authentication(session, request)
    if isinstance(result, Response):
        return result
    serialized_options = result.get("options") or {}
    return {
        "challenge": result["challenge"],
        "rp_id": result["rp_id"],
        "timeout": result["timeout"],
        "allow_credentials": serialized_options.get("allowCredentials", []),
    }
