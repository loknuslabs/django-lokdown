from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from lokdown.helpers.auth_flow_helper import disable_user_2fa
from lokdown.helpers.totp_helper import get_or_create_totp, has_totp_enabled
from lokdown.models import UserTimeBasedOneTimePasswords
from lokdown.serializers import (
    DisableTwoFAResponseSerializer,
    TwoFactorStatusResponseSerializer,
)


@extend_schema(
    summary="Get 2FA status",
    tags=["2FA"],
    responses={200: TwoFactorStatusResponseSerializer},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_2fa_status(request):
    if has_totp_enabled(request.user):
        two_fa = get_or_create_totp(request.user)
    else:
        two_fa = UserTimeBasedOneTimePasswords(user=request.user)
    return Response(TwoFactorStatusResponseSerializer(two_fa).data)


@extend_schema(
    summary="Disable 2FA",
    tags=["2FA"],
    responses={200: DisableTwoFAResponseSerializer},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def disable_2fa(request):
    disable_user_2fa(request.user)
    return Response(DisableTwoFAResponseSerializer({"message": "2FA disabled successfully"}).data)
