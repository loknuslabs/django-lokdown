"""
Resolve pending 2FA LoginSession from multiple client auth styles.

Supported sources (first match wins):
1. ``session_id`` in JSON body, form POST, or query string
2. Django session key (default ``admin_2fa_session_id``) for admin HTML flows
3. Bearer JWT — latest non-expired pending LoginSession for the authenticated user
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User
from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from lokdown.helpers.auth_flow_helper import validate_login_session
from lokdown.models import LoginSession


def get_admin_pending_session_key() -> str:
    return getattr(settings, "LOKDOWN_ADMIN_PENDING_SESSION_KEY", "admin_2fa_session_id")


def extract_pending_session_id(request) -> str | None:
    """Read explicit session_id from API body, form, or query."""
    data = getattr(request, "data", None)
    if data is not None:
        session_id = data.get("session_id")
        if session_id:
            return str(session_id)

    if hasattr(request, "POST"):
        session_id = request.POST.get("session_id")
        if session_id:
            return str(session_id)

    session_id = request.GET.get("session_id")
    if session_id:
        return str(session_id)

    return None


def extract_django_session_pending_id(request) -> str | None:
    """Read pending LoginSession id stored in Django session (admin cookie flow)."""
    if not hasattr(request, "session"):
        return None
    session_id = request.session.get(get_admin_pending_session_key())
    return str(session_id) if session_id else None


def store_admin_pending_session_id(request, session_id: str) -> None:
    """Persist pending LoginSession id in Django session for admin HTML flows."""
    if hasattr(request, "session"):
        request.session[get_admin_pending_session_key()] = session_id


def clear_admin_pending_session_id(request) -> None:
    if hasattr(request, "session") and get_admin_pending_session_key() in request.session:
        del request.session[get_admin_pending_session_key()]


def get_optional_authenticated_user(request) -> User | None:
    """Return user from DRF auth or Bearer JWT without requiring IsAuthenticated."""
    user = getattr(request, "user", None)
    if user is not None and user.is_authenticated and not isinstance(user, AnonymousUser):
        return user

    try:
        auth_result = JWTAuthentication().authenticate(request)
    except Exception:
        return None

    if auth_result:
        authenticated_user, _token = auth_result
        if authenticated_user.is_authenticated:
            return authenticated_user
    return None


def get_user_pending_login_session(user: User) -> LoginSession | None:
    """Latest open pending-2FA LoginSession for a JWT-authenticated user."""
    return (
        LoginSession.objects.filter(
            user=user,
            requires_2fa=True,
            is_authenticated=False,
            expires_at__gt=timezone.now(),
        )
        .order_by("-created_at")
        .first()
    )


def resolve_pending_session_id(request) -> str | None:
    """
    Resolve LoginSession id from body/query, Django session, or Bearer JWT.
    """
    session_id = extract_pending_session_id(request)
    if session_id:
        return session_id

    session_id = extract_django_session_pending_id(request)
    if session_id:
        return session_id

    user = get_optional_authenticated_user(request)
    if user:
        session = get_user_pending_login_session(user)
        if session:
            return session.session_id

    return None


def resolve_pending_login_session(request: Request) -> LoginSession | Response:
    """
    Resolve a pending LoginSession for pre-2FA API/admin calls.

    Returns LoginSession or a 400 Response when no session can be resolved.
    """
    session_id = resolve_pending_session_id(request)
    if not session_id:
        return Response(
            {
                "error": (
                    "No active session. Provide session_id in the request body, "
                    "use an admin session cookie, or send a Bearer token for a user "
                    "with a pending 2FA login."
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    return validate_login_session(session_id)
