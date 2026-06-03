from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from lokdown.helpers.auth_flow_helper import complete_login_with_tokens, verify_second_factor
from lokdown.serializers import (
    BackupCodeVerifyRequestSerializer,
    BackupCodeVerifyResponseSerializer,
    ErrorResponseSerializer,
)


@extend_schema(
    summary="Verify backup code and complete login",
    tags=["2FA Backup Code"],
    request=BackupCodeVerifyRequestSerializer,
    responses={
        200: BackupCodeVerifyResponseSerializer,
        401: ErrorResponseSerializer,
        429: OpenApiResponse(description="Too many attempts"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_backup_code_endpoint(request):
    serializer = BackupCodeVerifyRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    result = verify_second_factor(data["session_id"], None, None, data["backup_code"], request)
    if isinstance(result, Response):
        return result

    payload = complete_login_with_tokens(
        result,
        request,
        key_style="rest",
        message="Backup code verified successfully",
    )
    return Response(BackupCodeVerifyResponseSerializer(payload).data)
