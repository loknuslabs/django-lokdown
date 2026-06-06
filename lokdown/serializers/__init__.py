"""
Stable request/response serializers for lokdown API endpoints.
"""

from lokdown.serializers.auth import (
    AdminPasskeyAuthOptionsResponseSerializer,
    DisableTwoFAResponseSerializer,
    LoginInitRequestSerializer,
    LoginVerifyRequestSerializer,
    Pre2FALoginResponseSerializer,
    SimpleJwtTokenPairResponseSerializer,
    TokenPairResponseSerializer,
    TokenVerify2FARequestSerializer,
)
from lokdown.serializers.backup import (
    BackupCodeVerifyRequestSerializer,
    BackupCodeVerifyResponseSerializer,
)
from lokdown.serializers.models import (
    BackupCodesSerializer,
    LoginSessionSerializer,
    TwoFactorStatusResponseSerializer,
)
from lokdown.serializers.passkey import (
    PasskeyAuthOptionsRequestSerializer,
    PasskeyAuthOptionsResponseSerializer,
    PasskeyCredentialSerializer,
    PasskeyRemoveQuerySerializer,
    PasskeySetupRequestSerializer,
    PasskeySetupResponseSerializer,
    PasskeyVerifySetupRequestSerializer,
)
from lokdown.serializers.socialauth import (
    OAuthLoginUrlResponseSerializer,
    OAuthProviderEntrySerializer,
    OAuthProviderRedirectSerializer,
    OAuthProvidersResponseSerializer,
    OAuthSessionBridgeRequestSerializer,
    OAuthSessionBridgeResponseSerializer,
)
from lokdown.serializers.totp import (
    ErrorResponseSerializer,
    MessageResponseSerializer,
    TOTPSetupRequestSerializer,
    TOTPSetupResponseSerializer,
    TOTPVerifySetupRequestSerializer,
    TwoFactorSetupCompleteResponseSerializer,
)

# Backwards-compatible aliases
LoginInitSerializer = LoginInitRequestSerializer
LoginVerifySerializer = LoginVerifyRequestSerializer
TOTPSetupSerializer = TOTPSetupRequestSerializer
TOTPVerifySerializer = TOTPVerifySetupRequestSerializer
PasskeySetupSerializer = PasskeySetupRequestSerializer
PasskeyVerifySerializer = PasskeyVerifySetupRequestSerializer
BackupCodeSerializer = BackupCodeVerifyRequestSerializer
TwoFactorAuthSerializer = TwoFactorStatusResponseSerializer
AdminAuthOptionsResponseSerializer = AdminPasskeyAuthOptionsResponseSerializer

__all__ = [
    "AdminAuthOptionsResponseSerializer",
    "AdminPasskeyAuthOptionsResponseSerializer",
    "BackupCodeSerializer",
    "BackupCodeVerifyRequestSerializer",
    "BackupCodeVerifyResponseSerializer",
    "BackupCodesSerializer",
    "DisableTwoFAResponseSerializer",
    "ErrorResponseSerializer",
    "LoginInitRequestSerializer",
    "LoginInitSerializer",
    "LoginSessionSerializer",
    "LoginVerifyRequestSerializer",
    "LoginVerifySerializer",
    "MessageResponseSerializer",
    "OAuthLoginUrlResponseSerializer",
    "OAuthProviderEntrySerializer",
    "OAuthProviderRedirectSerializer",
    "OAuthProvidersResponseSerializer",
    "OAuthSessionBridgeRequestSerializer",
    "OAuthSessionBridgeResponseSerializer",
    "PasskeyAuthOptionsRequestSerializer",
    "PasskeyAuthOptionsResponseSerializer",
    "PasskeyCredentialSerializer",
    "PasskeyRemoveQuerySerializer",
    "PasskeySetupRequestSerializer",
    "PasskeySetupResponseSerializer",
    "PasskeySetupSerializer",
    "PasskeyVerifySetupRequestSerializer",
    "PasskeyVerifySerializer",
    "Pre2FALoginResponseSerializer",
    "SimpleJwtTokenPairResponseSerializer",
    "TokenPairResponseSerializer",
    "TokenVerify2FARequestSerializer",
    "TOTPSetupRequestSerializer",
    "TOTPSetupResponseSerializer",
    "TOTPSetupSerializer",
    "TOTPVerifySetupRequestSerializer",
    "TOTPVerifySerializer",
    "TwoFactorAuthSerializer",
    "TwoFactorSetupCompleteResponseSerializer",
    "TwoFactorStatusResponseSerializer",
]
