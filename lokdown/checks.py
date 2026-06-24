from django.conf import settings
from django.core.checks import Warning, register

from lokdown.helpers.feature_settings_helper import any_2fa_enrollment_enabled, socialauth_enabled
from lokdown.helpers.webauthn_settings_helper import parse_webauthn_origins

ADMIN_2FA_REQUIRED_CHECK_ID = "lokdown.W001"
WEBAUTHN_ORIGINS_CHECK_ID = "lokdown.W002"
SOCIALAUTH_SITE_ID_CHECK_ID = "lokdown.W003"
SOCIALAUTH_ADAPTER_CHECK_ID = "lokdown.W004"
ADMIN_2FA_FEATURES_CHECK_ID = "lokdown.W005"
ACCOUNT_ADAPTER_CHECK_ID = "lokdown.W006"


@register()
def check_admin_2fa_required(app_configs, **kwargs):
    if settings.DEBUG:
        return []
    if hasattr(settings, "ADMIN_2FA_REQUIRED"):
        return []

    return [
        Warning(
            "ADMIN_2FA_REQUIRED is not configured while DEBUG is False.",
            hint="Set ADMIN_2FA_REQUIRED = True in production to require 2FA for Django admin staff login.",
            id=ADMIN_2FA_REQUIRED_CHECK_ID,
        )
    ]


@register()
def check_webauthn_origins(app_configs, **kwargs):
    if settings.DEBUG:
        return []
    if parse_webauthn_origins():
        return []

    return [
        Warning(
            "WEBAUTHN_ORIGINS (or WEBAUTHN_ORIGIN) is not configured while DEBUG is False.",
            hint="Set WEBAUTHN_ORIGINS to the HTTPS origins allowed for WebAuthn ceremonies.",
            id=WEBAUTHN_ORIGINS_CHECK_ID,
        )
    ]


def _allauth_installed():
    return "allauth" in getattr(settings, "INSTALLED_APPS", [])


def _socialauth_in_use():
    """True when social auth is enabled, allauth is installed, and providers are configured."""
    if not socialauth_enabled():
        return False
    if not _allauth_installed():
        return False
    explicit = getattr(settings, "LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS", None)
    if explicit is not None:
        return bool(explicit)
    providers_cfg = getattr(settings, "SOCIALACCOUNT_PROVIDERS", {}) or {}
    return any(cfg.get("APPS") or cfg.get("APP") for cfg in providers_cfg.values())


@register()
def check_socialauth_site_id(app_configs, **kwargs):
    if not _socialauth_in_use():
        return []
    if getattr(settings, "SITE_ID", None) is not None:
        return []
    return [
        Warning(
            "SITE_ID is not set but SOCIALACCOUNT_PROVIDERS (or LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS) is configured.",
            hint="Add django.contrib.sites to INSTALLED_APPS and set SITE_ID = 1 (or your Site pk).",
            id=SOCIALAUTH_SITE_ID_CHECK_ID,
        )
    ]


@register()
def check_admin_2fa_features(app_configs, **kwargs):
    if not getattr(settings, "ADMIN_2FA_REQUIRED", False):
        return []
    if any_2fa_enrollment_enabled():
        return []
    return [
        Warning(
            "ADMIN_2FA_REQUIRED is True but both LOKDOWN_TOTP_ENABLED and LOKDOWN_PASSKEY_ENABLED are False.",
            hint=(
                "Enable at least one of LOKDOWN_TOTP_ENABLED or LOKDOWN_PASSKEY_ENABLED "
                "so staff can enroll in 2FA for admin access."
            ),
            id=ADMIN_2FA_FEATURES_CHECK_ID,
        )
    ]


@register()
def check_socialauth_adapter(app_configs, **kwargs):
    if not _socialauth_in_use():
        return []
    expected = "lokdown.socialauth.adapters.CustomSocialAccountAdapter"
    if getattr(settings, "SOCIALACCOUNT_ADAPTER", None) == expected:
        return []
    return [
        Warning(
            f"SOCIALACCOUNT_ADAPTER is not set to {expected}.",
            hint="Set SOCIALACCOUNT_ADAPTER so social signups receive email-based usernames from lokdown.",
            id=SOCIALAUTH_ADAPTER_CHECK_ID,
        )
    ]


@register()
def check_account_adapter(app_configs, **kwargs):
    if not _socialauth_in_use():
        return []
    expected = "lokdown.socialauth.adapters.CustomAccountAdapter"
    if getattr(settings, "ACCOUNT_ADAPTER", None) == expected:
        return []
    return [
        Warning(
            f"ACCOUNT_ADAPTER is not set to {expected}.",
            hint="Set ACCOUNT_ADAPTER so public registration is gated by LOKDOWN_ALLOW_PUBLIC_REGISTRATION.",
            id=ACCOUNT_ADAPTER_CHECK_ID,
        )
    ]
