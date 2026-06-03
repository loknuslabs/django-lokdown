"""
Lokdown URL configuration.

- ``urlpatterns`` — API routes (include under your project's ``api/`` prefix).
- ``override_admin_urls`` — call on the project root ``urlpatterns`` to wire admin + 2FA.
"""

from django.conf import settings
from django.contrib import admin
from django.shortcuts import redirect
from django.urls import include, path

from lokdown.admin_auth import (
    admin_2fa_backup_codes_view,
    admin_2fa_setup_passkey_view,
    admin_2fa_setup_view,
    admin_2fa_verify_totp_setup,
    admin_2fa_verify_view,
    admin_current_user_backup_codes,
    admin_current_user_passkey_setup,
    admin_current_user_totp_setup,
    admin_login_view,
)
from lokdown.control import auth_controller
from lokdown.control import backup_code_controller
from lokdown.control import passkey_controller
from lokdown.control import token_controller
from lokdown.control import totp_controller
from lokdown.control import twofa_controller
from lokdown.control.token_controller import CustomTokenObtainPairView, TaggedTokenRefreshView


# ---------------------------------------------------------------------------
# Admin URL helpers (for project root urlpatterns)
# ---------------------------------------------------------------------------


def redirect_usertwofactorauth(request):
    """Redirect legacy usertwofactorauth/ admin path to the TOTP model changelist."""
    return redirect("admin:lokdown_usertimebasedonetimepasswords_changelist")


def _current_user_setup_urls():
    """URLs for authenticated staff configuring their own 2FA in admin."""
    return [
        path(
            "current-user/totp-setup/",
            admin_current_user_totp_setup,
            name="admin_current_user_totp_setup",
        ),
        path(
            "current-user/passkey-setup/",
            admin_current_user_passkey_setup,
            name="admin_current_user_passkey_setup",
        ),
        path(
            "current-user/backup-codes/",
            admin_current_user_backup_codes,
            name="admin_current_user_backup_codes",
        ),
    ]


def _admin_2fa_urls():
    """Admin login + 2FA setup/verify routes (when ADMIN_2FA_REQUIRED is True)."""
    return [
        path("login/", admin_login_view, name="admin_login"),
        path("2fa/setup/", admin_2fa_setup_view, name="admin_2fa_setup"),
        path("2fa/verify/", admin_2fa_verify_view, name="admin_2fa_verify"),
        path("2fa/setup/passkey/", admin_2fa_setup_passkey_view, name="admin_2fa_setup_passkey"),
        path("2fa/verify/totp/", admin_2fa_verify_totp_setup, name="admin_2fa_verify_totp"),
        path("2fa/backup-codes/", admin_2fa_backup_codes_view, name="admin_2fa_backup_codes"),
    ]


def _build_admin_include_urls():
    """URLs included at project ``admin/``."""
    urls = []
    if getattr(settings, "ADMIN_2FA_REQUIRED", False):
        urls.extend(_admin_2fa_urls())
    urls.extend(_current_user_setup_urls())
    urls.append(path("", admin.site.urls))
    return urls


def _admin_redirect_patterns():
    return [
        path(
            "admin/lokdown/usertwofactorauth/",
            redirect_usertwofactorauth,
            name="admin_usertwofactorauth_redirect",
        ),
        path(
            "admin/lokdown/usertwofactorauth",
            redirect_usertwofactorauth,
            name="admin_usertwofactorauth_redirect_no_slash",
        ),
    ]


def override_admin_urls(urlpatterns):
    """
    Patch project urlpatterns: legacy admin redirects + lokdown admin/2FA routes.

    Usage::

        from lokdown.urls import override_admin_urls

        urlpatterns = [
            path("admin/", admin.site.urls),
            path("api/", include("lokdown.urls")),
            ...
        ]
        urlpatterns = override_admin_urls(urlpatterns)
    """
    redirect_patterns = _admin_redirect_patterns()
    admin_include = path("admin/", include(_build_admin_include_urls()))

    admin_pattern_index = None
    for i, pattern in enumerate(urlpatterns):
        if hasattr(pattern, "pattern") and "admin/" in str(pattern.pattern):
            admin_pattern_index = i
            break

    if admin_pattern_index is not None:
        urlpatterns[admin_pattern_index:admin_pattern_index] = redirect_patterns
        adjusted_index = admin_pattern_index + len(redirect_patterns)
        urlpatterns[adjusted_index] = admin_include
    else:
        urlpatterns.extend(redirect_patterns)
        urlpatterns.append(admin_include)

    return urlpatterns


# ---------------------------------------------------------------------------
# API urlpatterns (include as path("api/", include("lokdown.urls")))
# ---------------------------------------------------------------------------

app_name = "lokdown"

urlpatterns = [
    path("auth/token", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh", TaggedTokenRefreshView.as_view(), name="token_refresh"),
    path(
        "auth/token/verify",
        token_controller.TokenVerify2FAView.as_view(),
        name="token_verify_2fa",
    ),
    path("auth/login", auth_controller.login_init, name="login_init"),
    path("auth/verify", auth_controller.login_verify, name="login_verify"),
    path("auth/2fa/setup/totp", totp_controller.setup_totp, name="setup_totp"),
    path("auth/2fa/verify/totp", totp_controller.verify_totp_setup, name="verify_totp_setup"),
    path(
        "auth/2fa/passkey/credentials",
        passkey_controller.get_passkey_credentials,
        name="get_passkey_credentials",
    ),
    path(
        "auth/2fa/passkey/remove",
        passkey_controller.remove_passkey_credential,
        name="remove_passkey_credential",
    ),
    path("auth/2fa/passkey/setup", passkey_controller.setup_passkey, name="setup_passkey"),
    path(
        "auth/2fa/passkey/verify",
        passkey_controller.verify_passkey_setup,
        name="verify_passkey_setup",
    ),
    path(
        "auth/2fa/passkey/options",
        passkey_controller.get_passkey_auth_options,
        name="get_passkey_auth_options",
    ),
    path(
        "auth/2fa/verify/backup",
        backup_code_controller.verify_backup_code_endpoint,
        name="verify_backup_code",
    ),
    path("auth/2fa/status", twofa_controller.get_2fa_status, name="get_2fa_status"),
    path("auth/2fa/disable", twofa_controller.disable_2fa, name="disable_2fa"),
    path(
        "auth/admin/2fa/passkey/options",
        passkey_controller.admin_2fa_auth_options,
        name="admin_2fa_auth_options",
    ),
]
