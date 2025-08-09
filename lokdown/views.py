import base64
import uuid
from datetime import timedelta
from django.conf import settings
from django.contrib.auth import authenticate
from django.utils import timezone
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django_ratelimit.decorators import ratelimit
from .helpers.backup_codes_helper import has_backup_codes, get_or_create_backup_codes, verify_backup_code
from .helpers.passkey_helper import has_passkey_enabled, custom_generate_authentication_options, verify_passkey
from .helpers.session_helper import get_session, validate_session_data
from .helpers.totp_helper import has_totp_enabled, get_or_create_totp, verify_totp_login
from .models import LoginSession
from .serializers import (
    LoginInitSerializer,
    LoginVerifySerializer,
    TwoFactorAuthSerializer,
    DisableTwoFAResponseSerializer, AdminAuthOptionsResponseSerializer, AdminVerifyRequestSerializer,
    AdminVerifyResponseSerializer,
)
from lokdown.helpers.twofa_helper import (
    is_2fa_enabled,
)
from .helpers.common_helper import get_client_ip
import logging

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Initialize login with 2FA",
    description="Start login process and check if 2FA is required",
    tags=["Authentication"],
    request=LoginInitSerializer,
    responses={
        200: OpenApiResponse(description="Login initiated, 2FA required"),
        401: OpenApiResponse(description="Invalid credentials"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_init(request):
    """Initialize login and check 2FA requirements"""
    serializer = LoginInitSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    username = serializer.validated_data.get('username')
    password = serializer.validated_data.get('password')

    # Authenticate user
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    # Check 2FA status
    requires_2fa = is_2fa_enabled(user)

    if requires_2fa:
        # Create login session
        session_id = str(uuid.uuid4())
        LoginSession.objects.create(
            user=user,
            session_id=session_id,
            requires_2fa=True,
            expires_at=timezone.now() + timedelta(minutes=settings.TWOFA_SESSION_TIMEOUT),
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        return Response(
            {
                'session_id': session_id,
                'requires_2fa': True,
                'totp_enabled': has_totp_enabled(user),
                'passkey_enabled': has_passkey_enabled(user),
                'backup_codes_available': has_backup_codes(user),
            }
        )
    else:
        # No 2FA required, generate tokens directly
        refresh = RefreshToken.for_user(user)
        return Response(
            {'access_token': str(refresh.access_token), 'refresh_token': str(refresh), 'requires_2fa': False}
        )


@extend_schema(
    summary="Verify 2FA and complete login",
    description="Complete login by verifying 2FA token (TOTP, Passkey, or backup code)",
    tags=["Authentication"],
    request=LoginVerifySerializer,
    responses={
        200: OpenApiResponse(description="Login successful"),
        401: OpenApiResponse(description="Invalid 2FA token"),
        400: OpenApiResponse(description="Invalid session or missing token"),
        429: OpenApiResponse(description="Too many backup code attempts"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate=f'{settings.BACKUP_CODE_RATE_LIMIT}/m', method=['POST'], block=True)
def login_verify(request):
    """Verify 2FA and complete login"""
    serializer = LoginVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session_id = serializer.validated_data.get('session_id')
    totp_token = serializer.validated_data.get('totp_token')
    passkey_response = serializer.validated_data.get('passkey_response')
    backup_code = serializer.validated_data.get('backup_code')

    session = get_session(session_id, totp_token, passkey_response, backup_code, request)
    if type(session) is Response:
        return session

    # Generate tokens
    refresh = RefreshToken.for_user(session.user)
    session.is_authenticated = True
    session.save()

    return Response({'access_token': str(refresh.access_token), 'refresh_token': str(refresh), 'requires_2fa': False})


@extend_schema(
    summary="Get 2FA status",
    description="Get current 2FA status for user",
    tags=["2FA"],
    responses={
        200: TwoFactorAuthSerializer,
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_2fa_status(request):
    """Get 2FA status for current user"""
    # Only create TOTP record if user actually has TOTP enabled
    if has_totp_enabled(request.user):
        two_fa = get_or_create_totp(request.user)
        serializer = TwoFactorAuthSerializer(two_fa)
        return Response(serializer.data)
    else:
        # Create a dummy object for serialization
        from .models import UserTimeBasedOneTimePasswords

        dummy_obj = UserTimeBasedOneTimePasswords(user=request.user)
        serializer = TwoFactorAuthSerializer(dummy_obj)
        return Response(serializer.data)


@extend_schema(
    summary="Disable 2FA",
    description="Disable 2FA for user",
    tags=["2FA"],
    request=None,
    responses={
        200: DisableTwoFAResponseSerializer,
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def disable_2fa(request):
    """Disable 2FA for user"""
    # Only modify TOTP if user has it
    if has_totp_enabled(request.user):
        two_fa = get_or_create_totp(request.user)
        two_fa.totp_secret = None
        two_fa.save()

    # Remove passkey credentials
    request.user.passkey_credentials.all().delete()

    # Remove backup codes
    backup_codes_obj = get_or_create_backup_codes(request.user)
    backup_codes_obj.codes = []
    backup_codes_obj.save()

    return Response({'message': '2FA disabled successfully'})


@extend_schema(
    summary="Get admin 2FA authentication options",
    description="Generate passkey authentication options for admin login",
    tags=["2FA"],
    request=None,
    responses={
        200: AdminAuthOptionsResponseSerializer,
        400: OpenApiResponse(description="No active session"),
        500: OpenApiResponse(description="Failed to generate authentication options"),
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def admin_2fa_auth_options(request):
    """API endpoint for admin passkey authentication options"""
    session_id = request.session.get('admin_2fa_session_id')
    session, error = validate_session_data(session_id)
    if not session:
        return Response({'error': 'No active session'}, status=status.HTTP_400_BAD_REQUEST)

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

    return Response({'challenge': challenge_base64, 'rp_id': options.rp_id, 'timeout': options.timeout})


@extend_schema(
    summary="Verify admin 2FA",
    description="Verify admin 2FA using TOTP, passkey, or backup code",
    tags=["2FA"],
    request=AdminVerifyRequestSerializer,
    responses={
        200: AdminVerifyResponseSerializer,
        400: OpenApiResponse(description="Invalid or expired session"),
        401: OpenApiResponse(description="Invalid 2FA token"),
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def admin_2fa_verify_api(request):
    """API endpoint for admin 2FA verification"""
    session_id = request.data.get('session_id')
    totp_token = request.data.get('totp_token')
    passkey_response = request.data.get('passkey_response')
    backup_code = request.data.get('backup_code')

    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
    except LoginSession.DoesNotExist:
        return Response({'error': 'Invalid or expired session'}, status=status.HTTP_400_BAD_REQUEST)

    # Verify 2FA method
    if totp_token and has_totp_enabled(session.user):
        if verify_totp_login(session.user, totp_token):
            session.totp_verified = True
            session.save()
            return Response({'success': True})

    elif passkey_response and session.user.passkey_credentials.exists():
        if verify_passkey(session.user, passkey_response, session_id):
            session.passkey_verified = True
            session.save()
            return Response({'success': True})

    elif backup_code:
        if verify_backup_code(
            session.user, backup_code, get_client_ip(request), request.META.get('HTTP_USER_AGENT', '')
        ):
            session.totp_verified = True
            session.save()
            return Response({'success': True})

    return Response({'error': 'Invalid 2FA token'}, status=status.HTTP_401_UNAUTHORIZED)
