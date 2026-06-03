from django.conf import settings
from django.core.checks import Warning, register

from lokdown.helpers.webauthn_settings_helper import parse_webauthn_origins

ADMIN_2FA_REQUIRED_CHECK_ID = "lokdown.W001"
WEBAUTHN_ORIGINS_CHECK_ID = "lokdown.W002"


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
