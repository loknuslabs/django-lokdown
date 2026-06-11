from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from lokdown.helpers.auth_flow_helper import begin_totp_setup, complete_totp_setup
from lokdown.helpers.feature_settings_helper import feature_disabled_message, totp_enabled
from lokdown.helpers.totp_helper import has_totp_enabled
from lokdown.serializers import (
    ErrorResponseSerializer,
    TOTPSetupRequestSerializer,
    TOTPSetupResponseSerializer,
    TOTPVerifySetupRequestSerializer,
    TwoFactorSetupCompleteResponseSerializer,
)


def _totp_disabled_response():
    return Response(
        ErrorResponseSerializer({"error": feature_disabled_message("TOTP")}).data,
        status=status.HTTP_403_FORBIDDEN,
    )


@extend_schema(
    summary="Setup TOTP for authenticated user",
    tags=["2FA TOTP"],
    request=TOTPSetupRequestSerializer,
    responses={
        200: TOTPSetupResponseSerializer,
        403: ErrorResponseSerializer,
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def setup_totp(request):
    if not totp_enabled():
        return _totp_disabled_response()
    if has_totp_enabled(request.user):
        return Response(
            ErrorResponseSerializer({"error": "TOTP is already enabled"}).data,
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        payload = begin_totp_setup(request.user)
    except ValueError as exc:
        return Response(ErrorResponseSerializer({"error": str(exc)}).data, status=status.HTTP_403_FORBIDDEN)
    return Response(TOTPSetupResponseSerializer(payload).data)


@extend_schema(
    summary="Verify TOTP setup",
    tags=["2FA TOTP"],
    request=TOTPVerifySetupRequestSerializer,
    responses={
        200: TwoFactorSetupCompleteResponseSerializer,
        401: ErrorResponseSerializer,
        403: ErrorResponseSerializer,
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_totp_setup(request):
    if not totp_enabled():
        return _totp_disabled_response()
    serializer = TOTPVerifySetupRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    ok, error, backup_codes = complete_totp_setup(request.user, data["totp_token"])
    if not ok:
        code = status.HTTP_401_UNAUTHORIZED if error == "Invalid TOTP token" else status.HTTP_400_BAD_REQUEST
        if error == "Failed to complete TOTP setup":
            code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return Response(ErrorResponseSerializer({"error": error}).data, status=code)

    return Response(
        TwoFactorSetupCompleteResponseSerializer(
            {
                "message": "TOTP setup verified successfully",
                "backup_codes": backup_codes,
            }
        ).data
    )
