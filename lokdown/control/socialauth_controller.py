"""DRF endpoints documenting and assisting external-provider (OAuth) login."""

from __future__ import annotations

from urllib.parse import urlencode

from django.conf import settings
from django.urls import NoReverseMatch, reverse
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from lokdown.helpers.auth_flow_helper import initiate_password_login
from lokdown.serializers.socialauth import (
    OAuthLoginUrlResponseSerializer,
    OAuthProvidersResponseSerializer,
    OAuthSessionBridgeResponseSerializer,
)
from lokdown.socialauth.settings_helper import (
    get_enabled_social_providers,
    get_social_login_url_name,
)


def allauth_is_installed() -> bool:
    return "allauth" in getattr(settings, "INSTALLED_APPS", [])


def _service_unavailable() -> Response:
    return Response(
        {"error": "django-allauth is not installed or no OAuth providers are configured"},
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _default_oauth_next(request) -> str:
    url_name = getattr(settings, "LOKDOWN_SOCIALAUTH_CALLBACK_URL_NAME", "auth_callback")
    try:
        return reverse(url_name)
    except NoReverseMatch:
        return "/auth/callback"


def build_provider_login_url(request, provider_id: str, next_path: str | None = None) -> str:
    """Absolute OAuth start URL with optional allauth ``next`` query param."""
    login_path = reverse(get_social_login_url_name(provider_id))
    login_url = request.build_absolute_uri(login_path)
    if next_path:
        login_url = f"{login_url}?{urlencode({'next': next_path})}"
    return login_url


def bridge_oauth_session_to_lokdown(user, request) -> dict:
    """After OAuth Django session exists, return lokdown JWT or pre-2FA payload."""
    return initiate_password_login(user, request)


@extend_schema(
    summary="List configured OAuth providers",
    description=(
        "Returns browser login URLs for each provider in "
        "`SOCIALACCOUNT_PROVIDERS` / `LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS`. "
        "Not a substitute for `/accounts/` allauth routes — use `login_url` to start OAuth."
    ),
    tags=["OAuth"],
    responses={
        200: OAuthProvidersResponseSerializer,
        503: OpenApiResponse(description="allauth not installed or no providers configured"),
    },
)
@api_view(["GET"])
@permission_classes([AllowAny])
def oauth_providers(request):
    if not allauth_is_installed() or not get_enabled_social_providers():
        return _service_unavailable()

    next_path = request.query_params.get("next") or _default_oauth_next(request)
    providers = [
        {
            "id": provider_id,
            "login_url": build_provider_login_url(request, provider_id, next_path),
        }
        for provider_id in get_enabled_social_providers()
    ]
    return Response(OAuthProvidersResponseSerializer({"providers": providers}).data)


@extend_schema(
    summary="OAuth login URL for one provider",
    description=(
        "Returns the absolute URL to open in a browser for Google/GitHub/etc. "
        "After OAuth, allauth redirects to `next` (default: `auth_callback`). "
        "Then call `GET /api/auth/oauth/callback` with the session cookie to obtain JWTs."
    ),
    tags=["OAuth"],
    parameters=[
        OpenApiParameter(
            name="provider",
            type=str,
            location=OpenApiParameter.PATH,
            description="Provider id (google, github, …)",
        ),
        OpenApiParameter(
            name="next",
            type=str,
            location=OpenApiParameter.QUERY,
            description="Post-login redirect path for allauth (default: auth_callback)",
            required=False,
        ),
    ],
    responses={
        200: OAuthLoginUrlResponseSerializer,
        404: OpenApiResponse(description="Unknown provider"),
        503: OpenApiResponse(description="allauth not installed or provider not configured"),
    },
)
@api_view(["GET"])
@permission_classes([AllowAny])
def oauth_provider_login(request, provider: str):
    if not allauth_is_installed():
        return _service_unavailable()

    enabled = get_enabled_social_providers()
    if provider not in enabled:
        return Response({"error": f"Provider not configured: {provider}"}, status=status.HTTP_404_NOT_FOUND)

    next_path = request.query_params.get("next") or _default_oauth_next(request)
    try:
        login_url = build_provider_login_url(request, provider, next_path)
    except NoReverseMatch:
        return _service_unavailable()

    payload = {"provider": provider, "login_url": login_url, "next": next_path}
    return Response(OAuthLoginUrlResponseSerializer(payload).data)


@extend_schema(
    summary="Complete OAuth login (session to JWT)",
    description=(
        "Call after the user finishes OAuth and has a Django session cookie. "
        "Same response as `POST /api/auth/login` when 2FA is off, or returns `session_id` "
        "for `POST /api/auth/verify` when 2FA is enabled. "
        "Browser alternative: `GET /auth/callback` (non-API route)."
    ),
    tags=["OAuth"],
    responses={
        200: OAuthSessionBridgeResponseSerializer,
        401: OpenApiResponse(description="Not authenticated (no OAuth session)"),
        503: OpenApiResponse(description="allauth not installed"),
        500: OpenApiResponse(description="Failed to create lokdown login session"),
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def oauth_callback_bridge(request):
    if not allauth_is_installed():
        return _service_unavailable()

    try:
        payload = bridge_oauth_session_to_lokdown(request.user, request)
    except RuntimeError:
        return Response(
            {"error": "Failed to create authentication session"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return Response(OAuthSessionBridgeResponseSerializer(payload).data)
