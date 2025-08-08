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
from .helpers.backup_codes_helper import has_backup_codes, get_or_create_backup_codes
from .helpers.passkey_helper import has_passkey_enabled
from .helpers.session_helper import get_session
from .helpers.totp_helper import has_totp_enabled, get_or_create_2fa
from .models import LoginSession
from .serializers import (
    LoginInitSerializer,
    LoginVerifySerializer,
    TwoFactorAuthSerializer,
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
        two_fa = get_or_create_2fa(request.user)
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
    responses={
        200: OpenApiResponse(description="2FA disabled successfully"),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def disable_2fa(request):
    """Disable 2FA for user"""
    # Only modify TOTP if user has it
    if has_totp_enabled(request.user):
        two_fa = get_or_create_2fa(request.user)
        two_fa.totp_secret = None
        two_fa.save()

    # Remove passkey credentials
    request.user.passkey_credentials.all().delete()

    # Remove backup codes
    backup_codes_obj = get_or_create_backup_codes(request.user)
    backup_codes_obj.codes = []
    backup_codes_obj.save()

    return Response({'message': '2FA disabled successfully'})
