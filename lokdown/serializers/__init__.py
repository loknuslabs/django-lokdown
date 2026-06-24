"""
Stable request/response serializers for lokdown API endpoints.
"""

from lokdown.serializers.api_key import (
    ApiKeyCreateRequestSerializer,
    ApiKeyCreatedResponseSerializer,
    ApiKeyListResponseSerializer,
    ApiKeyMetadataSerializer,
    ApiKeyRevokeResponseSerializer,
)
from lokdown.serializers.auth import (
    AdminPasskeyAuthOptionsResponseSerializer,
    DisableTwoFAResponseSerializer,
    LoginInitRequestSerializer,
    LoginSessionRequestSerializer,
    LoginTotpVerifySetupRequestSerializer,
    LoginVerifyRequestSerializer,
    Pre2FALoginResponseSerializer,
    SimpleJwtTokenPairResponseSerializer,
    StaffLoginSetupCompleteResponseSerializer,
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
    "ApiKeyCreateRequestSerializer",
    "ApiKeyCreatedResponseSerializer",
    "ApiKeyListResponseSerializer",
    "ApiKeyMetadataSerializer",
    "ApiKeyRevokeResponseSerializer",
    "BackupCodeSerializer",
    "BackupCodeVerifyRequestSerializer",
    "BackupCodeVerifyResponseSerializer",
    "BackupCodesSerializer",
    "DisableTwoFAResponseSerializer",
    "ErrorResponseSerializer",
    "LoginInitRequestSerializer",
    "LoginInitSerializer",
    "LoginSessionRequestSerializer",
    "LoginSessionSerializer",
    "LoginTotpVerifySetupRequestSerializer",
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
    "StaffLoginSetupCompleteResponseSerializer",
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
