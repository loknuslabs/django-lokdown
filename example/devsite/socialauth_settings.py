"""Provider-specific SOCIALACCOUNT_PROVIDERS settings (credentials live in admin SocialApp)."""

from __future__ import annotations

# Providers installed in INSTALLED_APPS; OAuth client id/secret are configured in
# Django admin under Social applications (allauth.socialaccount.models.SocialApp).
SOCIALAUTH_SUPPORTED_PROVIDERS = ["google", "github"]


def build_socialaccount_providers() -> dict:
    """Non-credential provider options only — no APPS/APP entries."""
    return {
        "github": {"VERIFIED_EMAIL": True},
    }
