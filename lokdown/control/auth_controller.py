from django.contrib.auth import authenticate
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from lokdown.helpers.auth_flow_helper import (
    begin_passkey_registration,
    begin_totp_setup,
    complete_login_with_tokens,
    complete_staff_login_passkey_setup,
    complete_staff_login_totp_setup,
    initiate_password_login,
    validate_login_session,
    validate_staff_2fa_setup_session,
    verify_second_factor,
)
from lokdown.helpers.feature_settings_helper import passkey_enabled, totp_enabled
from lokdown.helpers.rate_limit_helper import check_login_init_rate_limit
from lokdown.serializers import (
    LoginInitRequestSerializer,
    LoginSessionRequestSerializer,
    LoginTotpVerifySetupRequestSerializer,
    LoginVerifyRequestSerializer,
    PasskeySetupResponseSerializer,
    PasskeyVerifySetupRequestSerializer,
    Pre2FALoginResponseSerializer,
    StaffLoginSetupCompleteResponseSerializer,
    TokenPairResponseSerializer,
    TOTPSetupResponseSerializer,
)


@extend_schema(
    summary="Initialize login with 2FA",
    tags=["Authentication"],
    request=LoginInitRequestSerializer,
    responses={
        200: Pre2FALoginResponseSerializer,
        401: OpenApiResponse(description="Invalid credentials"),
        429: OpenApiResponse(description="Too many authentication attempts"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_init(request):
    serializer = LoginInitRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    rate_limit_response = check_login_init_rate_limit(request, data["username"])
    if rate_limit_response:
        return rate_limit_response

    user = authenticate(
        username=data["username"],
        password=data["password"],
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
        429: OpenApiResponse(description="Too many authentication attempts"),
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


@extend_schema(
    summary="Begin TOTP setup during staff first login",
    tags=["Authentication"],
    request=LoginSessionRequestSerializer,
    responses={
        200: TOTPSetupResponseSerializer,
        400: OpenApiResponse(description="Invalid session"),
        403: OpenApiResponse(description="Not authorized"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_setup_totp(request):
    serializer = LoginSessionRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session_result = validate_login_session(serializer.validated_data["session_id"])
    if isinstance(session_result, Response):
        return session_result

    error_response = validate_staff_2fa_setup_session(session_result)
    if error_response:
        return error_response
    if not totp_enabled():
        return Response({"error": "TOTP support is disabled"}, status=status.HTTP_403_FORBIDDEN)

    try:
        payload = begin_totp_setup(session_result.user)
    except ValueError as exc:
        return Response({"error": str(exc)}, status=status.HTTP_403_FORBIDDEN)
    return Response(TOTPSetupResponseSerializer(payload).data)


@extend_schema(
    summary="Complete TOTP setup during staff first login",
    tags=["Authentication"],
    request=LoginTotpVerifySetupRequestSerializer,
    responses={
        200: StaffLoginSetupCompleteResponseSerializer,
        401: OpenApiResponse(description="Invalid TOTP token"),
        400: OpenApiResponse(description="Invalid session"),
        403: OpenApiResponse(description="Not authorized"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_verify_totp_setup(request):
    serializer = LoginTotpVerifySetupRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session_result = validate_login_session(serializer.validated_data["session_id"])
    if isinstance(session_result, Response):
        return session_result

    payload = complete_staff_login_totp_setup(
        session_result,
        serializer.validated_data["totp_token"],
        request,
        key_style="rest",
    )
    if isinstance(payload, Response):
        return payload
    return Response(StaffLoginSetupCompleteResponseSerializer(payload).data)


@extend_schema(
    summary="Begin passkey setup during staff first login",
    tags=["Authentication"],
    request=LoginSessionRequestSerializer,
    responses={
        200: PasskeySetupResponseSerializer,
        400: OpenApiResponse(description="Invalid session"),
        403: OpenApiResponse(description="Not authorized"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_setup_passkey(request):
    serializer = LoginSessionRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session_result = validate_login_session(serializer.validated_data["session_id"])
    if isinstance(session_result, Response):
        return session_result

    error_response = validate_staff_2fa_setup_session(session_result)
    if error_response:
        return error_response
    if not passkey_enabled():
        return Response({"error": "Passkey support is disabled"}, status=status.HTTP_403_FORBIDDEN)

    result = begin_passkey_registration(session_result.user, request)
    if isinstance(result, Response):
        return result
    return Response(PasskeySetupResponseSerializer(result).data)


@extend_schema(
    summary="Complete passkey setup during staff first login",
    tags=["Authentication"],
    request=PasskeyVerifySetupRequestSerializer,
    responses={
        200: StaffLoginSetupCompleteResponseSerializer,
        401: OpenApiResponse(description="Invalid passkey response"),
        400: OpenApiResponse(description="Invalid session"),
        403: OpenApiResponse(description="Not authorized"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_verify_passkey_setup(request):
    serializer = PasskeyVerifySetupRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session_result = validate_login_session(serializer.validated_data["session_id"])
    if isinstance(session_result, Response):
        return session_result

    payload = complete_staff_login_passkey_setup(
        session_result,
        serializer.validated_data["passkey_response"],
        request,
        key_style="rest",
    )
    if isinstance(payload, Response):
        return payload
    return Response(StaffLoginSetupCompleteResponseSerializer(payload).data)
