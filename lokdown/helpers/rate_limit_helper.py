"""Rate limiting helpers for authentication endpoints."""

from __future__ import annotations

from django.conf import settings
from django_ratelimit.core import is_ratelimited
from rest_framework import status
from rest_framework.response import Response


def auth_rate_limit_response() -> Response:
    return Response(
        {"error": "Too many authentication attempts"},
        status=status.HTTP_429_TOO_MANY_REQUESTS,
    )


def _username_rate_limit_key(username: str):
    def key(_group, _request):
        return username.lower()

    return key


def check_dual_auth_rate_limit(request, *, group: str, username: str, setting_name: str) -> Response | None:
    """Rate limit by client IP and username."""
    if getattr(request, "method", None) is None:
        request.method = "POST"

    rate = getattr(settings, setting_name, "10/m")

    if is_ratelimited(
        request,
        group=group,
        key="ip",
        rate=rate,
        method="POST",
        increment=True,
    ):
        return auth_rate_limit_response()

    if is_ratelimited(
        request,
        group=f"{group}_user",
        key=_username_rate_limit_key(username),
        rate=rate,
        method="POST",
        increment=True,
    ):
        return auth_rate_limit_response()

    return None


def check_login_init_rate_limit(request, username: str) -> Response | None:
    return check_dual_auth_rate_limit(
        request,
        group="login_init",
        username=username,
        setting_name="LOGIN_INIT_RATE_LIMIT",
    )


def check_totp_verify_rate_limit(request, username: str) -> Response | None:
    return check_dual_auth_rate_limit(
        request,
        group="totp_verify",
        username=username,
        setting_name="TOTP_VERIFY_RATE_LIMIT",
    )
