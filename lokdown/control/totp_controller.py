from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from lokdown.helpers.auth_flow_helper import begin_totp_setup, complete_totp_setup
from lokdown.serializers import (
    ErrorResponseSerializer,
    TOTPSetupRequestSerializer,
    TOTPSetupResponseSerializer,
    TOTPVerifySetupRequestSerializer,
    TwoFactorSetupCompleteResponseSerializer,
)


@extend_schema(
    summary="Setup TOTP for authenticated user",
    tags=["2FA TOTP"],
    request=TOTPSetupRequestSerializer,
    responses={200: TOTPSetupResponseSerializer},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def setup_totp(request):
    payload = begin_totp_setup(request.user)
    return Response(TOTPSetupResponseSerializer(payload).data)


@extend_schema(
    summary="Verify TOTP setup",
    tags=["2FA TOTP"],
    request=TOTPVerifySetupRequestSerializer,
    responses={
        200: TwoFactorSetupCompleteResponseSerializer,
        401: ErrorResponseSerializer,
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_totp_setup(request):
    serializer = TOTPVerifySetupRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    ok, error, backup_codes = complete_totp_setup(request.user, data["secret"], data["totp_token"])
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
