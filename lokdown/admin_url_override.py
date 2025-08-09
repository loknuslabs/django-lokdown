from django.urls import path, include
from django.contrib import admin
from django.conf import settings
from django.shortcuts import redirect
from .admin_auth import (
    admin_login_view,
    admin_2fa_setup_view,
    admin_2fa_verify_view,
    admin_2fa_setup_passkey_view,
    admin_2fa_verify_totp_setup,
    admin_2fa_backup_codes_view,
    admin_current_user_totp_setup,
    admin_current_user_passkey_setup,
    admin_current_user_backup_codes,
)


def redirect_usertwofactorauth(request):
    """Redirect usertwofactorauth/ to the correct model admin"""
    return redirect('admin:lokdown_usertimebasedonetimepasswords_changelist')


def get_admin_urls():
    """Get admin URLs with 2FA support"""
    return [
        path('login/', admin_login_view, name='admin_login'),
        path('2fa/setup/', admin_2fa_setup_view, name='admin_2fa_setup'),
        path('2fa/verify/', admin_2fa_verify_view, name='admin_2fa_verify'),
        path('2fa/setup/passkey/', admin_2fa_setup_passkey_view, name='admin_2fa_setup_passkey'),
        path('2fa/verify/totp/', admin_2fa_verify_totp_setup, name='admin_2fa_verify_totp'),
        path('2fa/backup-codes/', admin_2fa_backup_codes_view, name='admin_2fa_backup_codes'),
        # Current user setup URLs
        path('current-user/totp-setup/', admin_current_user_totp_setup, name='admin_current_user_totp_setup'),
        path('current-user/passkey-setup/', admin_current_user_passkey_setup, name='admin_current_user_passkey_setup'),
        path('current-user/backup-codes/', admin_current_user_backup_codes, name='admin_current_user_backup_codes'),
        path('', admin.site.urls),
    ]


def get_admin_urlpatterns():
    """Get admin URL patterns with 2FA support"""
    return [
        path('admin/', include(get_admin_urls())),
    ]


def override_admin_urls(urlpatterns):
    """
    Override admin URLs with 2FA support if ADMIN_2FA_REQUIRED is True
    Always include custom redirect patterns and current user setup URLs regardless of 2FA setting

    Usage in urls.py:
    from lokdown.admin_override import override_admin_urls

    urlpatterns = [
        # ... your other URLs
    ]

    # Override admin URLs with 2FA support
    urlpatterns = override_admin_urls(urlpatterns)
    """
    # Always add custom redirect patterns regardless of 2FA setting
    redirect_patterns = [
        path('admin/lokdown/usertwofactorauth/', redirect_usertwofactorauth, name='admin_usertwofactorauth_redirect'),
        path(
            'admin/lokdown/usertwofactorauth',
            redirect_usertwofactorauth,
            name='admin_usertwofactorauth_redirect_no_slash',
        ),
    ]

    # Find and process the admin pattern
    admin_pattern_index = None
    for i, pattern in enumerate(urlpatterns):
        if hasattr(pattern, 'pattern') and 'admin/' in str(pattern.pattern):
            admin_pattern_index = i
            break

    if admin_pattern_index is not None:
        # Insert redirect patterns before the admin pattern
        urlpatterns[admin_pattern_index:admin_pattern_index] = redirect_patterns

        if getattr(settings, 'ADMIN_2FA_REQUIRED', False):
            # Replace the admin pattern with our 2FA-enabled version
            # Adjust index since we inserted redirect patterns
            adjusted_index = admin_pattern_index + len(redirect_patterns)
            urlpatterns[adjusted_index] = path('admin/', include(get_admin_urls()))
        else:
            # When 2FA is not required, add current user patterns to the standard admin
            # Adjust index since we inserted redirect patterns
            adjusted_index = admin_pattern_index + len(redirect_patterns)

            def get_standard_admin_with_current_user():
                """Get standard admin URLs with current user setup URLs added"""
                return [
                    path(
                        'current-user/totp-setup/', admin_current_user_totp_setup, name='admin_current_user_totp_setup'
                    ),
                    path(
                        'current-user/passkey-setup/',
                        admin_current_user_passkey_setup,
                        name='admin_current_user_passkey_setup',
                    ),
                    path(
                        'current-user/backup-codes/',
                        admin_current_user_backup_codes,
                        name='admin_current_user_backup_codes',
                    ),
                    path('', admin.site.urls),
                ]

            urlpatterns[adjusted_index] = path('admin/', include(get_standard_admin_with_current_user()))
    else:
        # If no admin pattern found, add our 2FA-enabled admin URLs
        if getattr(settings, 'ADMIN_2FA_REQUIRED', False):
            urlpatterns.extend(redirect_patterns + get_admin_urlpatterns())
        else:
            # Add redirect patterns and standard admin with current user URLs
            def get_standard_admin_with_current_user():
                """Get standard admin URLs with current user setup URLs added"""
                return [
                    path(
                        'current-user/totp-setup/', admin_current_user_totp_setup, name='admin_current_user_totp_setup'
                    ),
                    path(
                        'current-user/passkey-setup/',
                        admin_current_user_passkey_setup,
                        name='admin_current_user_passkey_setup',
                    ),
                    path(
                        'current-user/backup-codes/',
                        admin_current_user_backup_codes,
                        name='admin_current_user_backup_codes',
                    ),
                    path('', admin.site.urls),
                ]

            urlpatterns.extend(redirect_patterns + [path('admin/', include(get_standard_admin_with_current_user()))])

    return urlpatterns
