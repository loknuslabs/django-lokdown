"""OAuth callback URL resolution and validation for lokdown social login."""

from __future__ import annotations

from urllib.parse import urlparse

from django.conf import settings
from django.urls import NoReverseMatch, reverse

from lokdown.socialauth.settings_helper import get_headless_browser_redirect_path


class InvalidOAuthCallbackUrlError(ValueError):
    """Raised when a callback URL fails lokdown or allauth safety checks."""


def get_allowed_oauth_callback_origins() -> list[str]:
    """Return ``LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS`` (may be empty)."""
    origins = getattr(settings, "LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS", None)
    if not origins:
        return []
    return [str(origin).strip().rstrip("/") for origin in origins if str(origin).strip()]


def _default_oauth_callback_url(request) -> str:
    url_name = getattr(settings, "LOKDOWN_SOCIALAUTH_CALLBACK_URL_NAME", "auth_callback")
    try:
        return request.build_absolute_uri(reverse(url_name))
    except NoReverseMatch:
        return request.build_absolute_uri("/auth/callback")


def _normalize_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/").lower()


def _request_origin(request) -> str:
    return _normalize_origin(request.build_absolute_uri("/"))


def is_safe_oauth_callback_url(request, url: str) -> bool:
    """
    Validate ``callback_url`` using allauth ``is_safe_url`` and optional
    ``LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS``.

    The API host origin is always permitted (for server-side ``auth_callback``).
    When ``LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS`` is non-empty, SPA origins
    must appear in that list.
    """
    if "allauth" not in getattr(settings, "INSTALLED_APPS", []):
        return False

    from allauth.account.adapter import get_adapter
    from allauth.core import context

    with context.request_context(request):
        if not get_adapter().is_safe_url(url):
            return False

    url_origin = _normalize_origin(url)
    if url_origin == _request_origin(request):
        return True

    allowed_origins = get_allowed_oauth_callback_origins()
    if not allowed_origins:
        return True

    normalized_allowed = {_normalize_origin(origin) for origin in allowed_origins}
    return url_origin in normalized_allowed


def resolve_oauth_callback_url(request, callback_url: str | None = None) -> str:
    """Resolve relative/absolute callback input and validate it."""
    if not callback_url:
        resolved = _default_oauth_callback_url(request)
    elif callback_url.startswith("/"):
        resolved = request.build_absolute_uri(callback_url)
    else:
        resolved = callback_url

    if not is_safe_oauth_callback_url(request, resolved):
        raise InvalidOAuthCallbackUrlError("Invalid or disallowed callback_url")

    return resolved


def build_headless_provider_redirect_url(request) -> str:
    """Absolute URL for allauth headless browser provider redirect (POST form target)."""
    return request.build_absolute_uri(get_headless_browser_redirect_path())


def build_oauth_redirect_metadata(
    request,
    provider_id: str,
    callback_url: str | None = None,
) -> dict[str, str]:
    """Validated headless OAuth start metadata for one provider."""
    return {
        "provider": provider_id,
        "redirect_url": build_headless_provider_redirect_url(request),
        "callback_url": resolve_oauth_callback_url(request, callback_url),
        "redirect_method": "POST",
    }
