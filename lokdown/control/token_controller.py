from django.contrib.auth import authenticate
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from drf_spectacular.utils import extend_schema, OpenApiResponse

from lokdown.helpers.auth_flow_helper import (
    complete_login_with_tokens,
    initiate_password_login,
    verify_second_factor,
)
from lokdown.helpers.twofa_helper import is_2fa_enabled
from lokdown.serializers import (
    SimpleJwtTokenPairResponseSerializer,
    TokenVerify2FARequestSerializer,
)


@extend_schema(
    tags=["Authentication"],
    summary="Refresh JWT token",
    description="Takes a valid refresh token and returns a new access token.",
)
class TaggedTokenRefreshView(TokenRefreshView):
    pass


def _flatten_validation_detail(detail):
    """Normalize DRF ValidationError.detail for JSON responses."""
    if not isinstance(detail, dict):
        return detail
    bool_keys = {"requires_2fa", "totp_enabled", "passkey_enabled", "backup_codes_available"}
    flat = {}
    for key, value in detail.items():
        if isinstance(value, list) and value:
            item = value[0]
        else:
            item = value
        if hasattr(item, "code"):
            item = str(item)
        if key in bool_keys and isinstance(item, str):
            item = item == "True"
        flat[key] = item
    return flat


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        user = authenticate(username=attrs.get("username"), password=attrs.get("password"))
        if not user:
            raise serializers.ValidationError("Invalid credentials")

        if is_2fa_enabled(user):
            request = self.context["request"]
            try:
                payload = initiate_password_login(user, request)
            except RuntimeError:
                raise serializers.ValidationError("Failed to create authentication session")
            raise serializers.ValidationError({**payload, "message": "2FA verification required"})

        return super().validate(attrs)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    @extend_schema(
        summary="Obtain JWT token pair",
        tags=["Authentication"],
        responses={
            200: SimpleJwtTokenPairResponseSerializer,
            401: OpenApiResponse(description="Invalid credentials or 2FA required"),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as e:
            flat = _flatten_validation_detail(e.detail)
            if isinstance(flat, dict) and flat.get("requires_2fa"):
                return Response(flat, status=status.HTTP_401_UNAUTHORIZED)
            return Response(flat, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class TokenVerify2FAView(TokenObtainPairView):
    @extend_schema(
        summary="Complete token generation after 2FA",
        tags=["Authentication"],
        request=TokenVerify2FARequestSerializer,
        responses={
            200: SimpleJwtTokenPairResponseSerializer,
            401: OpenApiResponse(description="Invalid 2FA token"),
            400: OpenApiResponse(description="Invalid session"),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = TokenVerify2FARequestSerializer(data=request.data)
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

        payload = complete_login_with_tokens(result, request, key_style="simplejwt")
        return Response(SimpleJwtTokenPairResponseSerializer(payload).data)
