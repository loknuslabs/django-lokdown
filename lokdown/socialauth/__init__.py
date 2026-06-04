"""django-allauth integration: social login middleware, adapters, and settings helpers."""

from lokdown.socialauth.settings_helper import (
    LOKDOWN_ALLAUTH_BASE_APPS,
    get_allauth_recommended_settings,
    get_enabled_social_providers,
    get_provider_installed_apps,
    get_social_login_url_name,
    social_login_path_prefix,
)

__all__ = [
    "AutoRedirectAccountLoginToGoogleMiddleware",
    "AutoRedirectAccountLoginToSocialMiddleware",
    "CustomSocialAccountAdapter",
    "LOKDOWN_ALLAUTH_BASE_APPS",
    "RedirectAuthenticatedGoogleLoginMiddleware",
    "RedirectAuthenticatedSocialLoginMiddleware",
    "get_allauth_recommended_settings",
    "get_enabled_social_providers",
    "get_provider_installed_apps",
    "get_social_login_url_name",
    "social_login_path_prefix",
]


def __getattr__(name):
    """Lazy imports so ``manage.py check`` works before allauth is in INSTALLED_APPS."""
    if name == "CustomSocialAccountAdapter":
        from lokdown.socialauth.adapters import CustomSocialAccountAdapter

        return CustomSocialAccountAdapter
    if name in (
        "RedirectAuthenticatedSocialLoginMiddleware",
        "RedirectAuthenticatedGoogleLoginMiddleware",
    ):
        from lokdown.socialauth.middleware import RedirectAuthenticatedSocialLoginMiddleware

        return RedirectAuthenticatedSocialLoginMiddleware
    if name in (
        "AutoRedirectAccountLoginToSocialMiddleware",
        "AutoRedirectAccountLoginToGoogleMiddleware",
    ):
        from lokdown.socialauth.middleware import AutoRedirectAccountLoginToSocialMiddleware

        return AutoRedirectAccountLoginToSocialMiddleware
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
