"""Settings helpers for user-tied API keys."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.utils import timezone


def api_keys_enabled() -> bool:
    """Return True when API key generation and authentication are enabled."""
    return bool(getattr(settings, "LOKDOWN_API_KEYS_ENABLED", False))


def api_key_prefix() -> str:
    """Prefix prepended to generated API keys (default ``lk_``)."""
    return getattr(settings, "LOKDOWN_API_KEY_PREFIX", "lk_")


def api_key_max_lifespan_days() -> int | None:
    """
    Maximum allowed lifespan in days from creation.

    ``None`` means no upper bound is enforced by settings.
    """
    value = getattr(settings, "LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS", None)
    if value is None:
        return None
    return int(value)


def api_keys_allow_indefinite() -> bool:
    """Return True when users may create keys without an expiry."""
    return bool(getattr(settings, "LOKDOWN_API_KEY_ALLOW_INDEFINITE", True))


def api_key_auth_header() -> str:
    """HTTP header used for API key authentication (default ``Authorization``)."""
    return getattr(settings, "LOKDOWN_API_KEY_AUTH_HEADER", "Authorization")


def api_key_auth_scheme() -> str:
    """Auth scheme prefix in the header value (default ``Api-Key``)."""
    return getattr(settings, "LOKDOWN_API_KEY_AUTH_SCHEME", "Api-Key")


def max_allowed_expires_at(from_time=None):
    """Latest ``expires_at`` allowed by ``LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS``."""
    max_days = api_key_max_lifespan_days()
    if max_days is None:
        return None
    base = from_time or timezone.now()
    return base + timedelta(days=max_days)
