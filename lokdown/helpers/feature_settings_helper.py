"""Feature flags for optional lokdown capabilities."""

from __future__ import annotations

from django.conf import settings


def passkey_enabled() -> bool:
    """Return True when passkey enrollment and login are enabled."""
    return bool(getattr(settings, "LOKDOWN_PASSKEY_ENABLED", False))


def totp_enabled() -> bool:
    """Return True when TOTP enrollment and login are enabled."""
    return bool(getattr(settings, "LOKDOWN_TOTP_ENABLED", False))


def socialauth_enabled() -> bool:
    """Return True when social account (OAuth) login is enabled."""
    return bool(getattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED", False))


def any_2fa_enrollment_enabled() -> bool:
    """Return True when at least one primary 2FA enrollment method is enabled."""
    return passkey_enabled() or totp_enabled()


def feature_disabled_message(feature: str) -> str:
    """Human-readable error when a feature flag is off."""
    return f"{feature} support is disabled"
