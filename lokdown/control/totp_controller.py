from django.conf import settings
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
import logging

from lokdown.helpers.totp_helper import (
    generate_totp_secret,
    generate_totp_qr_code,
    verify_totp_token_setup,
    setup_totp_complete,
)
from lokdown.serializers import TOTPSetupSerializer, TOTPVerifySerializer

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Setup TOTP for user",
    description="Generate TOTP secret and QR code for authenticator app",
    tags=["2FA TOTP"],
    request=TOTPSetupSerializer,
    responses={
        200: OpenApiResponse(description="TOTP setup successful"),
        400: OpenApiResponse(description="Invalid user ID"),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def setup_totp(request):
    """Setup TOTP for user"""
    serializer = TOTPSetupSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    user_id = serializer.validated_data['user_id']
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate TOTP secret and QR code
    secret = generate_totp_secret()
    qr_base64 = generate_totp_qr_code(secret, user)

    # Generate provisioning URI
    import pyotp

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.email or user.username, issuer_name=settings.WEBAUTHN_RP_NAME)

    return Response(
        {
            'secret': secret,
            'qr_code': qr_base64,
            'provisioning_uri': provisioning_uri,
        }
    )


@extend_schema(
    summary="Verify TOTP setup",
    description="Verify TOTP token to complete setup",
    tags=["2FA TOTP"],
    request=TOTPVerifySerializer,
    responses={
        200: OpenApiResponse(description="TOTP verification successful"),
        401: OpenApiResponse(description="Invalid TOTP token"),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_totp_setup(request):
    """Verify TOTP setup"""
    serializer = TOTPVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    user_id = serializer.validated_data['user_id']
    totp_token = serializer.validated_data['totp_token']
    secret = serializer.validated_data.get('secret')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)

    if secret and totp_token:
        # Verify the TOTP token
        if verify_totp_token_setup(secret, totp_token):
            # Complete TOTP setup
            if setup_totp_complete(user, secret):
                return Response({'message': 'TOTP setup verified successfully'})
            else:
                return Response(
                    {'error': 'Failed to complete TOTP setup'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            return Response({'error': 'Invalid TOTP token'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'Missing secret or token'}, status=status.HTTP_400_BAD_REQUEST)
