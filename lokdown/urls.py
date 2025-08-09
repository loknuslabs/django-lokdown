from django.urls import path
from . import views
from . import admin_auth
from .control import token_controller
from .control import passkey_controller
from .control import backup_code_controller
from .control import totp_controller
from .control.token_controller import CustomTokenObtainPairView, TaggedTokenRefreshView


app_name = 'lokdown'

urlpatterns = [
    path('api/token', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TaggedTokenRefreshView.as_view(), name='token_refresh'),
    # 2FA-enabled login endpoints
    path('auth/login', views.login_init, name='login_init'),
    path('auth/verify', views.login_verify, name='login_verify'),
    path('auth/passkey/options', passkey_controller.get_passkey_auth_options, name='get_passkey_auth_options'),
    # Token verification endpoint for 2FA
    path('auth/token/verify', token_views.TokenVerify2FAView.as_view(), name='token_verify_2fa'),
    # 2FA management endpoints
    path('auth/2fa/setup/totp', totp_controller.setup_totp, name='setup_totp'),
    path('auth/2fa/verify/totp', totp_controller.verify_totp_setup, name='verify_totp_setup'),
    path('auth/2fa/setup/passkey', passkey_controller.setup_passkey, name='setup_passkey'),
    path('auth/2fa/verify/passkey', passkey_controller.verify_passkey_setup, name='verify_passkey_setup'),
    path('auth/2fa/status', views.get_2fa_status, name='get_2fa_status'),
    path('auth/2fa/disable', views.disable_2fa, name='disable_2fa'),
    path('auth/2fa/passkey/credentials', passkey_controller.get_passkey_credentials, name='get_passkey_credentials'),
    path('auth/2fa/passkey/remove', passkey_controller.remove_passkey_credential, name='remove_passkey_credential'),
    path('auth/2fa/verify/backup', backup_code_controller.verify_backup_code_endpoint, name='verify_backup_code'),
    # Admin 2FA API endpoints
    path('admin/2fa/auth-options', admin_auth.admin_2fa_auth_options, name='admin_2fa_auth_options'),
    path('admin/2fa/verify-api', admin_auth.admin_2fa_verify_api, name='admin_2fa_verify_api'),
    # Admin backup codes display
    path('admin/backup-codes/display', admin_auth.admin_backup_codes_display, name='admin_backup_codes_display'),
]
