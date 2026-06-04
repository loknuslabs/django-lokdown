"""Settings helpers for django-allauth + lokdown social login."""

from __future__ import annotations

from django.conf import settings

from lokdown.socialauth.providers import (
    CUSTOM_PROVIDER_SLUGS,
    CUSTOM_LOGIN_URL_NAMES,
    SOCIALAUTH_PROVIDER_APPS,
)

LOKDOWN_ALLAUTH_BASE_APPS = [
    "django.contrib.sites",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
]


def get_provider_installed_apps(provider_ids: list[str] | None = None) -> list[str]:
    """Return ``INSTALLED_APPS`` entries for the given provider ids (or all configured)."""
    ids = provider_ids or get_enabled_social_providers()
    apps = []
    for provider_id in ids:
        app = SOCIALAUTH_PROVIDER_APPS.get(provider_id)
        if app and app not in apps:
            apps.append(app)
    return apps


def get_enabled_social_providers() -> list[str]:
    """
    Provider ids enabled for lokdown middleware and URL helpers.

    Uses ``LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS`` when set; otherwise keys from
    ``SOCIALACCOUNT_PROVIDERS`` that have ``APPS`` or ``APP`` configured.
    """
    explicit = getattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", None)
    if explicit is not None:
        return list(explicit)

    providers_cfg = getattr(settings, "SOCIALACCOUNT_PROVIDERS", {}) or {}
    enabled = []
    for provider_id, cfg in providers_cfg.items():
        if cfg.get("APPS") or cfg.get("APP"):
            enabled.append(provider_id)
    return enabled


def get_social_login_url_name(provider_id: str) -> str:
    """Reverse name for initiating OAuth (e.g. ``google_login``)."""
    return CUSTOM_LOGIN_URL_NAMES.get(provider_id, f"{provider_id}_login")


def social_login_path_prefix(provider_id: str) -> str:
    """Path prefix for provider login, e.g. ``/accounts/google/login``."""
    account_prefix = getattr(settings, "LOKDOWN_SOCIALAUTH_ACCOUNT_URL_PREFIX", "accounts").strip("/")
    slug = CUSTOM_PROVIDER_SLUGS.get(provider_id, provider_id)
    return f"/{account_prefix}/{slug}/login"


def get_auto_redirect_provider() -> str | None:
    """
    Provider id for ``AutoRedirectAccountLoginToSocialMiddleware``.

    ``SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER`` wins; legacy
    ``SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_GOOGLE`` maps to ``google``.
    """
    provider = getattr(settings, "SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER", None)
    if provider:
        return provider
    if getattr(settings, "SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_GOOGLE", False):
        return "google"
    return None


def get_allauth_recommended_settings() -> dict:
    """Suggested Django settings for social login alongside lokdown JWT/2FA APIs."""
    return {
        "SITE_ID": 1,
        "AUTHENTICATION_BACKENDS": [
            "django.contrib.auth.backends.ModelBackend",
            "allauth.account.auth_backends.AuthenticationBackend",
        ],
        "SOCIALACCOUNT_ADAPTER": "lokdown.socialauth.adapters.CustomSocialAccountAdapter",
        "ACCOUNT_EMAIL_VERIFICATION": "optional",
        "ACCOUNT_LOGIN_METHODS": {"email"},
        "ACCOUNT_SIGNUP_FIELDS": ["email*", "password1*", "password2*"],
        "SOCIALACCOUNT_EMAIL_AUTHENTICATION": True,
        "SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT": True,
    }


def get_lokdown_socialauth_middleware() -> list[str]:
    """Default middleware class paths (append after ``AccountMiddleware``)."""
    return [
        "allauth.account.middleware.AccountMiddleware",
        "lokdown.socialauth.middleware.RedirectAuthenticatedSocialLoginMiddleware",
        "lokdown.socialauth.middleware.AutoRedirectAccountLoginToSocialMiddleware",
    ]
