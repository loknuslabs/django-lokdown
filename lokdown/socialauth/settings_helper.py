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
    "allauth.headless",
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


def _providers_with_settings_apps() -> list[str]:
    providers_cfg = getattr(settings, "SOCIALACCOUNT_PROVIDERS", {}) or {}
    return [provider_id for provider_id, cfg in providers_cfg.items() if cfg.get("APPS") or cfg.get("APP")]


def get_admin_social_providers() -> list[str]:
    """Provider ids with a ``SocialApp`` linked to ``SITE_ID`` (django-allauth admin)."""
    if "allauth" not in getattr(settings, "INSTALLED_APPS", []):
        return []
    site_id = getattr(settings, "SITE_ID", None)
    if site_id is None:
        return []

    try:
        from allauth.socialaccount.models import SocialApp
    except ImportError:
        return []

    return sorted(SocialApp.objects.filter(sites__id=site_id).values_list("provider", flat=True).distinct())


def get_enabled_social_providers() -> list[str]:
    """
    Provider ids enabled for lokdown middleware and URL helpers.

    Returns an empty list when ``LOKDOWN_SOCIALAUTH_ENABLED`` is ``False``.

    Resolution order:

    1. ``LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS`` when set — if no provider has
       ``APPS``/``APP`` in ``SOCIALACCOUNT_PROVIDERS``, only providers with an
       admin ``SocialApp`` for ``SITE_ID`` are returned.
    2. Keys from ``SOCIALACCOUNT_PROVIDERS`` with ``APPS``/``APP`` in settings.
    3. Admin ``SocialApp`` records for ``SITE_ID``.
    """
    from lokdown.helpers.feature_settings_helper import socialauth_enabled

    if not socialauth_enabled():
        return []

    explicit = getattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", None)
    settings_apps = _providers_with_settings_apps()

    if explicit is not None:
        if settings_apps:
            return list(explicit)
        admin_apps = get_admin_social_providers()
        return [provider_id for provider_id in explicit if provider_id in admin_apps]

    if settings_apps:
        return settings_apps

    return get_admin_social_providers()


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


def get_headless_url_prefix() -> str:
    """URL prefix for allauth headless routes (default ``_allauth``)."""
    return getattr(settings, "LOKDOWN_SOCIALAUTH_HEADLESS_URL_PREFIX", "_allauth").strip("/")


def get_headless_browser_redirect_path(url_prefix: str | None = None) -> str:
    """Path to POST when starting OAuth in headless browser mode."""
    prefix = (url_prefix or get_headless_url_prefix()).strip("/")
    return f"/{prefix}/browser/v1/auth/provider/redirect"


def get_headless_browser_config_path(url_prefix: str | None = None) -> str:
    """Path to GET provider metadata in headless browser mode."""
    prefix = (url_prefix or get_headless_url_prefix()).strip("/")
    return f"/{prefix}/browser/v1/config"


def get_headless_frontend_urls(spa_base_url: str) -> dict[str, str]:
    """
    Suggested ``HEADLESS_FRONTEND_URLS`` for SPA-owned account flows.

    ``spa_base_url`` should be the SPA origin or path prefix (no trailing slash),
    e.g. ``http://localhost:5173`` or ``https://app.example.com``.
    """
    base = spa_base_url.rstrip("/")
    return {
        "account_confirm_email": f"{base}/account/verify-email/{{key}}",
        "account_reset_password": f"{base}/account/password/reset",
        "account_reset_password_from_key": f"{base}/account/password/reset/key/{{key}}",
        "account_signup": f"{base}/account/signup",
        "socialaccount_login_error": f"{base}/oauth/callback",
    }


def get_allauth_recommended_settings() -> dict:
    """Suggested Django settings for social login alongside lokdown JWT/2FA APIs."""
    return {
        "SITE_ID": 1,
        "AUTHENTICATION_BACKENDS": [
            "django.contrib.auth.backends.ModelBackend",
            "allauth.account.auth_backends.AuthenticationBackend",
        ],
        "SOCIALACCOUNT_ADAPTER": "lokdown.socialauth.adapters.CustomSocialAccountAdapter",
        "ACCOUNT_ADAPTER": "lokdown.socialauth.adapters.CustomAccountAdapter",
        "ACCOUNT_EMAIL_VERIFICATION": "optional",
        "ACCOUNT_LOGIN_METHODS": {"email"},
        "ACCOUNT_SIGNUP_FIELDS": ["email*", "password1*", "password2*"],
        "SOCIALACCOUNT_EMAIL_AUTHENTICATION": True,
        "SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT": True,
        # SPA owns login UI; keep /accounts/* for OAuth callbacks only.
        "HEADLESS_ONLY": True,
        # Django defaults to /accounts/profile/, which allauth no longer serves.
        "LOGIN_REDIRECT_URL": "/",
    }


def get_lokdown_socialauth_middleware() -> list[str]:
    """Default middleware class paths (append after ``AccountMiddleware``)."""
    return [
        "allauth.account.middleware.AccountMiddleware",
        "lokdown.socialauth.middleware.RedirectAuthenticatedSocialLoginMiddleware",
        "lokdown.socialauth.middleware.AutoRedirectAccountLoginToSocialMiddleware",
    ]
