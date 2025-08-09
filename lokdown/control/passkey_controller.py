import base64
from django.utils import timezone
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
import logging
from lokdown.helpers.passkey_helper import (
    generate_passkey_options,
    create_login_session_for_passkey,
    verify_passkey_registration,
    setup_passkey_backup_codes,
    has_passkey_enabled,
    custom_generate_authentication_options,
)
from lokdown.helpers.twofa_helper import serialize_webauthn_options, handle_2fa_error
from lokdown.models import LoginSession, PasskeyCredential
from lokdown.serializers import (
    PasskeySetupSerializer,
    PasskeyVerifySerializer,
    PasskeyCredentialSerializer,
    PasskeyAuthOptionsRequestSerializer,
    PasskeyAuthOptionsResponseSerializer,
)

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Setup passkey for user",
    description="Generate passkey registration options",
    tags=["2FA Passkey"],
    request=PasskeySetupSerializer,
    responses={
        200: OpenApiResponse(description="Passkey setup options generated"),
        400: OpenApiResponse(description="Invalid user ID"),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def setup_passkey(request):
    """Setup passkey for user"""
    serializer = PasskeySetupSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    user_id = serializer.validated_data['user_id']
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate passkey options
    options = generate_passkey_options(user)
    if not options:
        return Response({'error': 'Failed to generate passkey options'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Create login session for passkey setup
    session_id = create_login_session_for_passkey(user, options.challenge, request)
    if not session_id:
        return Response({'error': 'Failed to create login session'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Serialize options
    serialized_options = serialize_webauthn_options(options)

    return Response({'session_id': session_id, 'options': serialized_options})


@extend_schema(
    summary="Verify passkey setup",
    description="Verify passkey registration response",
    tags=["2FA Passkey"],
    request=PasskeyVerifySerializer,
    responses={
        200: OpenApiResponse(description="Passkey setup verified successfully"),
        401: OpenApiResponse(description="Invalid passkey response"),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_passkey_setup(request):
    """Verify passkey setup"""
    serializer = PasskeyVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    user_id = serializer.validated_data['user_id']
    passkey_response = serializer.validated_data['passkey_response']

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Get the session for challenge verification
        session = user.login_sessions.last()
        if not session or not session.challenge:
            return Response({'error': 'No valid session found'}, status=status.HTTP_400_BAD_REQUEST)

        # Verify the passkey registration response
        verification = verify_passkey_registration(passkey_response, session.challenge)
        if not verification:
            return Response({'error': 'Invalid passkey response'}, status=status.HTTP_401_UNAUTHORIZED)

        # Complete passkey setup
        if setup_passkey_backup_codes(user, verification):
            return Response({'message': 'Passkey setup verified successfully'})
        else:
            return Response({'error': 'Failed to complete passkey setup'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        error_msg = handle_2fa_error(e, user, "Passkey setup")
        return Response({'error': error_msg}, status=status.HTTP_401_UNAUTHORIZED)


@extend_schema(
    summary="Get passkey authentication options",
    description="Generate passkey authentication options for login",
    tags=["2FA Passkey"],
    request=PasskeyAuthOptionsRequestSerializer,
    responses={
        200: PasskeyAuthOptionsResponseSerializer,
        400: OpenApiResponse(description="Invalid session"),
        500: OpenApiResponse(description="Failed to generate options"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def get_passkey_auth_options(request):
    """Generate passkey authentication options for login"""
    session_id = request.data.get('session_id')

    # Validate session
    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
    except LoginSession.DoesNotExist:
        return Response({'error': 'Invalid or expired session'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if user has passkey enabled
    if not has_passkey_enabled(session.user):
        return Response({'error': 'User does not have passkey enabled'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate authentication options
    options = custom_generate_authentication_options()
    if not options:
        return Response(
            {'error': 'Failed to generate authentication options'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    # Store challenge in session
    challenge_base64 = base64.b64encode(options.challenge).decode('utf-8')
    session.challenge = challenge_base64
    session.save()

    # Serialize options for frontend
    serialized_options = serialize_webauthn_options(options)

    return Response(
        {
            'challenge': challenge_base64,
            'rp_id': options.rp_id,
            'timeout': options.timeout,
            'options': serialized_options,
        }
    )


@extend_schema(
    summary="Get passkey credentials",
    description="Get all passkey credentials for user",
    tags=["2FA Passkey"],
    responses={
        200: PasskeyCredentialSerializer(many=True),
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_passkey_credentials(request):
    """Get passkey credentials for user"""
    credentials = request.user.passkey_credentials.all()
    serializer = PasskeyCredentialSerializer(credentials, many=True)
    return Response(serializer.data)


@extend_schema(
    summary="Remove passkey credential",
    description="Remove specific passkey credential",
    tags=["2FA Passkey"],
    parameters=[
        OpenApiParameter(name='credential_id', type=str, location='query'),
    ],
    responses={
        200: OpenApiResponse(description="Passkey credential removed"),
        400: OpenApiResponse(description="Credential not found"),
    },
)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def remove_passkey_credential(request):
    """Remove passkey credential"""
    credential_id = request.GET.get('credential_id')
    if not credential_id:
        return Response({'error': 'credential_id parameter required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        credential = request.user.passkey_credentials.get(credential_id=credential_id)
        credential.delete()
        return Response({'message': 'Passkey credential removed'})
    except PasskeyCredential.DoesNotExist:
        return Response({'error': 'Credential not found'}, status=status.HTTP_400_BAD_REQUEST)
