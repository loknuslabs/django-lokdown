from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status

from lokdown.helpers.auth_flow_helper import (
    admin_passkey_auth_options_payload,
    begin_passkey_authentication,
    begin_passkey_registration,
    complete_passkey_registration,
    validate_login_session,
    validate_session_data,
)
from lokdown.helpers.twofa_helper import handle_2fa_error
from lokdown.serializers import (
    AdminPasskeyAuthOptionsResponseSerializer,
    ErrorResponseSerializer,
    MessageResponseSerializer,
    PasskeyAuthOptionsRequestSerializer,
    PasskeyAuthOptionsResponseSerializer,
    PasskeyCredentialSerializer,
    PasskeySetupRequestSerializer,
    PasskeySetupResponseSerializer,
    PasskeyVerifySetupRequestSerializer,
    TwoFactorSetupCompleteResponseSerializer,
)


@extend_schema(
    summary="Setup passkey for authenticated user",
    tags=["2FA Passkey"],
    request=PasskeySetupRequestSerializer,
    responses={200: PasskeySetupResponseSerializer},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def setup_passkey(request):
    result = begin_passkey_registration(request.user, request)
    if isinstance(result, Response):
        return result
    return Response(PasskeySetupResponseSerializer(result).data)


@extend_schema(
    summary="Verify passkey setup",
    tags=["2FA Passkey"],
    request=PasskeyVerifySetupRequestSerializer,
    responses={
        200: TwoFactorSetupCompleteResponseSerializer,
        401: ErrorResponseSerializer,
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_passkey_setup(request):
    serializer = PasskeyVerifySetupRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    try:
        ok, error, backup_codes = complete_passkey_registration(
            request.user,
            data["session_id"],
            data["passkey_response"],
            request=request,
        )
        if not ok:
            return Response(ErrorResponseSerializer({"error": error}).data, status=status.HTTP_401_UNAUTHORIZED)
        return Response(
            TwoFactorSetupCompleteResponseSerializer(
                {
                    "message": "Passkey setup verified successfully",
                    "backup_codes": backup_codes,
                }
            ).data
        )
    except Exception as e:
        handle_2fa_error(e, request.user, "Passkey setup")
        return Response(
            ErrorResponseSerializer({"error": "Passkey setup failed"}).data,
            status=status.HTTP_401_UNAUTHORIZED,
        )


@extend_schema(
    summary="Get passkey authentication options for login",
    tags=["2FA Passkey"],
    request=PasskeyAuthOptionsRequestSerializer,
    responses={200: PasskeyAuthOptionsResponseSerializer},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def get_passkey_auth_options(request):
    serializer = PasskeyAuthOptionsRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session = validate_login_session(serializer.validated_data["session_id"])
    if isinstance(session, Response):
        return session

    result = begin_passkey_authentication(session)
    if isinstance(result, Response):
        return result
    return Response(PasskeyAuthOptionsResponseSerializer(result).data)


@extend_schema(
    summary="List passkey credentials",
    tags=["2FA Passkey"],
    responses={200: PasskeyCredentialSerializer(many=True)},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_passkey_credentials(request):
    credentials = request.user.passkey_credentials.all()
    return Response(PasskeyCredentialSerializer(credentials, many=True).data)


@extend_schema(
    summary="Remove passkey credential",
    tags=["2FA Passkey"],
    parameters=[OpenApiParameter(name="credential_id", type=str, location="query", required=True)],
    responses={200: MessageResponseSerializer},
)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def remove_passkey_credential(request):
    credential_id = request.GET.get("credential_id")
    if not credential_id:
        return Response(
            ErrorResponseSerializer({"error": "credential_id parameter required"}).data,
            status=status.HTTP_400_BAD_REQUEST,
        )
    deleted, _ = request.user.passkey_credentials.filter(credential_id=credential_id).delete()
    if not deleted:
        return Response(
            ErrorResponseSerializer({"error": "Credential not found"}).data,
            status=status.HTTP_400_BAD_REQUEST,
        )
    return Response(MessageResponseSerializer({"message": "Passkey credential removed"}).data)


@extend_schema(
    summary="Admin passkey authentication options",
    description="Generate passkey challenge for admin 2FA verify page (uses Django session cookie).",
    tags=["2FA Passkey"],
    request=None,
    responses={
        200: AdminPasskeyAuthOptionsResponseSerializer,
        400: OpenApiResponse(description="No active session"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def admin_2fa_auth_options(request):
    from lokdown.helpers.request_auth_helper import get_admin_pending_session_key

    session_id = request.session.get(get_admin_pending_session_key())
    session, _error = validate_session_data(session_id, request)
    if not session:
        return Response(
            ErrorResponseSerializer({"error": "No active session"}).data,
            status=status.HTTP_400_BAD_REQUEST,
        )

    payload = admin_passkey_auth_options_payload(session, request)
    if isinstance(payload, Response):
        return payload
    return Response(AdminPasskeyAuthOptionsResponseSerializer(payload).data)
