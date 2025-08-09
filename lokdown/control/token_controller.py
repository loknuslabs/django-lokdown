import uuid
from datetime import timedelta
from django.conf import settings
from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from drf_spectacular.utils import extend_schema, OpenApiResponse
from lokdown.helpers.backup_codes_helper import has_backup_codes
from lokdown.helpers.passkey_helper import has_passkey_enabled
from lokdown.helpers.session_helper import get_session
from lokdown.helpers.totp_helper import has_totp_enabled
from lokdown.models import LoginSession
from lokdown.helpers.twofa_helper import is_2fa_enabled
from lokdown.helpers.common_helper import get_client_ip


@extend_schema(
    tags=["Authentication"],
    summary="Refresh JWT token",
    description="Takes a valid refresh token and returns a new access token.",
)
class TaggedTokenRefreshView(TokenRefreshView):
    pass


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom serializer that handles 2FA requirements"""

    def validate(self, attrs):
        # First, authenticate the user
        user = authenticate(username=attrs.get('username'), password=attrs.get('password'))

        if not user:
            raise serializers.ValidationError('Invalid credentials')

        # Check if user has 2FA enabled
        if is_2fa_enabled(user):
            # Create a login session for 2FA verification
            session_id = str(uuid.uuid4())
            LoginSession.objects.create(
                user=user,
                session_id=session_id,
                requires_2fa=True,
                expires_at=timezone.now() + timedelta(minutes=settings.TWOFA_SESSION_TIMEOUT),
                ip_address=get_client_ip(self.context['request']),
                user_agent=self.context['request'].META.get('HTTP_USER_AGENT', ''),
            )

            # Return session info instead of tokens
            raise serializers.ValidationError(
                {
                    'requires_2fa': True,
                    'session_id': session_id,
                    'totp_enabled': has_totp_enabled(user),
                    'passkey_enabled': has_passkey_enabled(user),
                    'backup_codes_available': has_backup_codes(user),
                    'message': '2FA verification required',
                }
            )

        # No 2FA required, proceed with normal token generation
        return super().validate(attrs)


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom token obtain view that handles 2FA requirements"""

    serializer_class = CustomTokenObtainPairSerializer

    @extend_schema(
        summary="Obtain JWT token pair",
        description="Authenticate user and obtain access/refresh tokens. If 2FA is enabled, returns session info for "
        "2FA verification.",
        tags=["Authentication"],
        responses={
            200: OpenApiResponse(description="Tokens obtained successfully"),
            401: OpenApiResponse(description="Invalid credentials or 2FA required"),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as e:
            # Check if this is a 2FA requirement response
            if isinstance(e.detail, dict) and e.detail.get('requires_2fa'):
                return Response(e.detail, status=status.HTTP_401_UNAUTHORIZED)
            return Response(e.detail, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class TokenVerify2FAView(TokenObtainPairView):
    """View to complete token generation after 2FA verification"""

    @extend_schema(
        summary="Complete token generation after 2FA",
        description="Complete token generation after successful 2FA verification",
        tags=["Authentication"],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'session_id': {'type': 'string'},
                    'totp_token': {'type': 'string'},
                    'passkey_response': {'type': 'object'},
                    'backup_code': {'type': 'string'},
                },
            }
        },
        responses={
            200: OpenApiResponse(description="Tokens generated successfully"),
            401: OpenApiResponse(description="Invalid 2FA token"),
            400: OpenApiResponse(description="Invalid session or missing token"),
        },
    )
    def post(self, request, *args, **kwargs):
        session_id = request.data.get('session_id')
        totp_token = request.data.get('totp_token')
        passkey_response = request.data.get('passkey_response')
        backup_code = request.data.get('backup_code')

        if not session_id:
            return Response({'error': 'session_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        session = get_session(session_id, totp_token, passkey_response, backup_code, request)
        if type(session) is Response:
            return session

        # Generate tokens
        refresh = RefreshToken.for_user(session.user)
        session.is_authenticated = True
        session.save()

        return Response({'access': str(refresh.access_token), 'refresh': str(refresh), 'requires_2fa': False})
