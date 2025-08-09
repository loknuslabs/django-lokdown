# ============================================================================
# Session Management Helper Functions
# ============================================================================
import uuid
import logging
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from lokdown.helpers.backup_codes_helper import verify_backup_code
from lokdown.helpers.common_helper import get_client_ip
from lokdown.helpers.passkey_helper import has_passkey_enabled, verify_passkey
from lokdown.helpers.totp_helper import has_totp_enabled, verify_totp_login
from lokdown.models import LoginSession

logger = logging.getLogger(__name__)


def create_authentication_session(user, request=None):
    """Create an authentication session for 2FA verification"""
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
            session.user_agent = request.META.get('HTTP_USER_AGENT', '')
            session.save()

        return session_id
    except Exception as e:
        logger.error(f"Failed to create authentication session for user {user.username}: {str(e)}")
        return None


def validate_session_data(session_id):
    """Validate session data for 2FA operations"""
    if not session_id:
        return None, "No session ID provided"

    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
        return session, None
    except LoginSession.DoesNotExist:
        return None, "Invalid or expired session"


def get_session(session_id, totp_token, passkey_response, backup_code, request):
    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
    except LoginSession.DoesNotExist:
        return Response({'error': 'Invalid or expired session'}, status=status.HTTP_400_BAD_REQUEST)

    # Verify 2FA method
    if totp_token and has_totp_enabled(session.user):
        if verify_totp_login(session.user, totp_token):
            session.totp_verified = True
            session.save()
        else:
            return Response({'error': 'Invalid TOTP token'}, status=status.HTTP_401_UNAUTHORIZED)

    elif passkey_response and has_passkey_enabled(session.user):
        if verify_passkey(session.user, passkey_response, session_id):
            session.passkey_verified = True
            session.save()
        else:
            return Response({'error': 'Invalid passkey response'}, status=status.HTTP_401_UNAUTHORIZED)

    elif backup_code:
        if verify_backup_code(
            session.user, backup_code, get_client_ip(request), request.META.get('HTTP_USER_AGENT', '')
        ):
            session.totp_verified = True  # Mark as verified for backup codes
            session.save()
        else:
            return Response({'error': 'Invalid backup code'}, status=status.HTTP_401_UNAUTHORIZED)

    else:
        return Response({'error': 'No valid 2FA method provided'}, status=status.HTTP_400_BAD_REQUEST)

    return True
