from django.contrib.auth import authenticate
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from lokdown.helpers.auth_flow_helper import (
    complete_login_with_tokens,
    initiate_password_login,
    verify_second_factor,
)
from lokdown.serializers import (
    LoginInitRequestSerializer,
    LoginVerifyRequestSerializer,
    Pre2FALoginResponseSerializer,
    TokenPairResponseSerializer,
)


@extend_schema(
    summary="Initialize login with 2FA",
    tags=["Authentication"],
    request=LoginInitRequestSerializer,
    responses={
        200: Pre2FALoginResponseSerializer,
        401: OpenApiResponse(description="Invalid credentials"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_init(request):
    serializer = LoginInitRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(
        username=serializer.validated_data["username"],
        password=serializer.validated_data["password"],
    )
    if not user:
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        payload = initiate_password_login(user, request)
    except RuntimeError:
        return Response(
            {"error": "Failed to create authentication session"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    response_serializer = (
        Pre2FALoginResponseSerializer(payload) if payload.get("requires_2fa") else TokenPairResponseSerializer(payload)
    )
    return Response(response_serializer.data)


@extend_schema(
    summary="Verify 2FA and complete login",
    tags=["Authentication"],
    request=LoginVerifyRequestSerializer,
    responses={
        200: TokenPairResponseSerializer,
        401: OpenApiResponse(description="Invalid 2FA token"),
        400: OpenApiResponse(description="Invalid session or missing token"),
        429: OpenApiResponse(description="Too many backup code attempts"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_verify(request):
    serializer = LoginVerifyRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    result = verify_second_factor(
        data["session_id"],
        data.get("totp_token"),
        data.get("passkey_response"),
        data.get("backup_code"),
        request,
    )
    if isinstance(result, Response):
        return result

    payload = complete_login_with_tokens(result, request, key_style="rest")
    return Response(TokenPairResponseSerializer(payload).data)
