from django.conf import settings
from django.utils import timezone
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django_ratelimit.decorators import ratelimit

from lokdown.helpers.backup_codes_helper import verify_backup_code
from lokdown.helpers.common_helper import get_client_ip
from lokdown.models import LoginSession
from lokdown.serializers import BackupCodeSerializer


@extend_schema(
    summary="Verify backup code",
    description="Verify backup code with strict rate limiting (10 attempts per minute)",
    tags=["2FA Backup Code"],
    request=BackupCodeSerializer,
    responses={
        200: OpenApiResponse(description="Backup code verified successfully"),
        401: OpenApiResponse(description="Invalid backup code"),
        429: OpenApiResponse(description="Too many backup code attempts"),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate=f'{settings.BACKUP_CODE_RATE_LIMIT}/m', method=['POST'], block=True)
def verify_backup_code_endpoint(request):
    """Dedicated endpoint for backup code verification with strict rate limiting"""
    serializer = BackupCodeSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session_id = serializer.validated_data.get('session_id')
    backup_code = serializer.validated_data.get('backup_code')

    # Get session
    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
    except LoginSession.DoesNotExist:
        return Response({'error': 'Invalid or expired session'}, status=status.HTTP_400_BAD_REQUEST)

    # Get client IP and user agent
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    # Verify backup code
    if verify_backup_code(session.user, backup_code, ip_address, user_agent):
        session.totp_verified = True
        session.save()

        # Generate tokens
        refresh = RefreshToken.for_user(session.user)
        session.is_authenticated = True
        session.save()

        return Response(
            {
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'requires_2fa': False,
                'message': 'Backup code verified successfully',
            }
        )
    else:
        return Response({'error': 'Invalid backup code'}, status=status.HTTP_401_UNAUTHORIZED)
