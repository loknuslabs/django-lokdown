"""DRF endpoints documenting and assisting external-provider (OAuth) login."""

from __future__ import annotations

from django.conf import settings
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from lokdown.helpers.auth_flow_helper import initiate_password_login
from lokdown.serializers.socialauth import (
    OAuthProviderRedirectSerializer,
    OAuthProvidersResponseSerializer,
    OAuthSessionBridgeRequestSerializer,
    OAuthSessionBridgeResponseSerializer,
)
from lokdown.socialauth.callback_url import InvalidOAuthCallbackUrlError
from lokdown.socialauth.settings_helper import get_enabled_social_providers


def allauth_is_installed() -> bool:
    return "allauth" in getattr(settings, "INSTALLED_APPS", [])


def _service_unavailable() -> Response:
    return Response(
        {"error": "django-allauth is not installed or no OAuth providers are configured"},
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _invalid_callback_url_response() -> Response:
    return Response(
        {"callback_url": ["Invalid or disallowed callback_url"]},
        status=status.HTTP_400_BAD_REQUEST,
    )


def bridge_oauth_session_to_lokdown(user, request) -> dict:
    """After OAuth Django session exists, return lokdown JWT or pre-2FA payload."""
    return initiate_password_login(user, request)


@extend_schema(
    summary="List configured OAuth providers",
    description=(
        "Returns headless redirect metadata for each provider configured via Django admin "
        "Social applications (or `SOCIALACCOUNT_PROVIDERS`). "
        "Prefer `GET /_allauth/browser/v1/config` for dynamic provider discovery; "
        "this endpoint pre-fills `callback_url` for lokdown's JWT bridge. "
        "`callback_url` must pass allauth `is_safe_url` and, when set, "
        "`LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS`. "
        "SPA flow: POST a form to `redirect_url` with `provider`, `callback_url`, "
        "`process=login`, and `csrfmiddlewaretoken`, then call "
        "`POST /api/auth/oauth/callback` with session cookie and CSRF header."
    ),
    tags=["OAuth"],
    parameters=[
        OpenApiParameter(
            name="callback_url",
            type=str,
            location=OpenApiParameter.QUERY,
            description=(
                "Post-OAuth redirect URL for allauth headless. Use your SPA callback route "
                "(absolute URL). Defaults to project `auth_callback` when omitted."
            ),
            required=False,
        ),
        OpenApiParameter(
            name="next",
            type=str,
            location=OpenApiParameter.QUERY,
            description="Alias for `callback_url` (legacy query param).",
            required=False,
        ),
    ],
    responses={
        200: OAuthProvidersResponseSerializer,
        400: OpenApiResponse(description="Invalid or disallowed callback_url"),
        503: OpenApiResponse(description="allauth not installed or no providers configured"),
    },
)
@api_view(["GET"])
@permission_classes([AllowAny])
def oauth_providers(request):
    if not allauth_is_installed() or not get_enabled_social_providers():
        return _service_unavailable()

    callback_url = request.query_params.get("callback_url") or request.query_params.get("next")
    try:
        providers = [
            OAuthProviderRedirectSerializer.for_provider(request, provider_id, callback_url).data
            for provider_id in get_enabled_social_providers()
        ]
    except InvalidOAuthCallbackUrlError:
        return _invalid_callback_url_response()

    return Response(OAuthProvidersResponseSerializer({"providers": providers}).data)


@extend_schema(
    summary="OAuth redirect metadata for one provider",
    description=(
        "Returns headless redirect metadata to start browser OAuth for Google/GitHub/etc. "
        "POST a form to `redirect_url` with `provider`, `callback_url`, `process=login`, "
        "and `csrfmiddlewaretoken` (synchronous form submit, not XHR). "
        "`callback_url` must pass allauth `is_safe_url` and, when set, "
        "`LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS`. "
        "After OAuth completes, call `POST /api/auth/oauth/callback` from your SPA with "
        "session cookie and `X-CSRFToken` to receive JWTs or a pre-2FA `session_id`."
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
            name="callback_url",
            type=str,
            location=OpenApiParameter.QUERY,
            description=(
                "Post-OAuth redirect URL passed to allauth headless. Prefer your SPA callback "
                "(absolute URL). Defaults to project `auth_callback` when omitted."
            ),
            required=False,
        ),
        OpenApiParameter(
            name="next",
            type=str,
            location=OpenApiParameter.QUERY,
            description="Alias for `callback_url` (legacy query param).",
            required=False,
        ),
    ],
    responses={
        200: OAuthProviderRedirectSerializer,
        400: OpenApiResponse(description="Invalid or disallowed callback_url"),
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

    callback_url = request.query_params.get("callback_url") or request.query_params.get("next")
    try:
        serializer = OAuthProviderRedirectSerializer.for_provider(request, provider, callback_url)
    except InvalidOAuthCallbackUrlError:
        return _invalid_callback_url_response()

    return Response(serializer.data)


@extend_schema(
    summary="Complete OAuth login (session to JWT)",
    description=(
        "Primary SPA callback endpoint. Call after OAuth when the browser has a Django "
        "session cookie (`sessionid` on the API origin). Returns JSON only — same shape as "
        "`POST /api/auth/login` when 2FA is off, or `session_id` + flags for "
        "`POST /api/auth/verify` when 2FA is enabled. "
        "Authenticates via Django **session cookie** (`sessionid`), not Bearer JWT. "
        "Requires **POST** with CSRF protection (`X-CSRFToken` header or "
        "`csrfmiddlewaretoken` body field). Same-origin SPAs can proxy `/accounts/*` and "
        "`/api/*` through Vite (e.g. `http://localhost:5173`) so the cookie is set on one "
        "host. Cross-origin SPAs need `fetch(..., { credentials: 'include' })` plus "
        "`CSRF_TRUSTED_ORIGINS` / `CORS_ALLOW_CREDENTIALS`."
    ),
    tags=["OAuth"],
    request=OAuthSessionBridgeRequestSerializer,
    responses={
        200: OAuthSessionBridgeResponseSerializer,
        401: OpenApiResponse(description="Not authenticated (no OAuth session cookie)"),
        403: OpenApiResponse(description="CSRF verification failed"),
        503: OpenApiResponse(description="allauth not installed"),
        500: OpenApiResponse(description="Failed to create lokdown login session"),
    },
)
@api_view(["POST"])
@authentication_classes([SessionAuthentication])
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
