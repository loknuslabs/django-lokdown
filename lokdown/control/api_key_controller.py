from datetime import timedelta

from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from lokdown.helpers.api_key_helper import (
    create_user_api_key,
    is_api_key_active,
    list_user_api_keys,
    revoke_api_key as revoke_api_key_for_user,
    validate_requested_expires_at,
)
from lokdown.helpers.api_key_settings_helper import api_keys_enabled
from lokdown.serializers import (
    ApiKeyCreateRequestSerializer,
    ApiKeyCreatedResponseSerializer,
    ApiKeyListResponseSerializer,
    ApiKeyMetadataSerializer,
    ApiKeyRevokeResponseSerializer,
    ErrorResponseSerializer,
)


def _api_keys_disabled_response():
    return Response(
        ErrorResponseSerializer({"error": "API keys are disabled"}).data,
        status=status.HTTP_403_FORBIDDEN,
    )


def _serialize_metadata(api_key) -> dict:
    return ApiKeyMetadataSerializer(
        {
            "id": api_key.id,
            "name": api_key.name,
            "prefix": api_key.prefix,
            "created_at": api_key.created_at,
            "last_used_at": api_key.last_used_at,
            "expires_at": api_key.expires_at,
            "is_active": is_api_key_active(api_key),
        }
    ).data


@extend_schema(
    methods=["GET"],
    summary="List API keys for the authenticated user",
    tags=["API Keys"],
    responses={
        200: ApiKeyListResponseSerializer,
        403: ErrorResponseSerializer,
    },
)
@extend_schema(
    methods=["POST"],
    summary="Create an API key",
    tags=["API Keys"],
    request=ApiKeyCreateRequestSerializer,
    responses={
        201: ApiKeyCreatedResponseSerializer,
        400: ErrorResponseSerializer,
        403: ErrorResponseSerializer,
    },
)
@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def manage_api_keys(request):
    if not api_keys_enabled():
        return _api_keys_disabled_response()

    if request.method == "GET":
        keys = list_user_api_keys(request.user)
        return Response(ApiKeyListResponseSerializer({"api_keys": [_serialize_metadata(k) for k in keys]}).data)

    serializer = ApiKeyCreateRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    expires_at = None
    if data.get("expires_in_days") is not None:
        requested = timezone.now() + timedelta(days=data["expires_in_days"])
        try:
            expires_at = validate_requested_expires_at(requested)
        except ValueError as exc:
            return Response(ErrorResponseSerializer({"error": str(exc)}).data, status=status.HTTP_400_BAD_REQUEST)
    else:
        try:
            expires_at = validate_requested_expires_at(None)
        except ValueError as exc:
            return Response(ErrorResponseSerializer({"error": str(exc)}).data, status=status.HTTP_400_BAD_REQUEST)

    try:
        api_key, raw_key = create_user_api_key(
            request.user,
            name=data.get("name", ""),
            expires_at=expires_at,
        )
    except ValueError as exc:
        return Response(ErrorResponseSerializer({"error": str(exc)}).data, status=status.HTTP_400_BAD_REQUEST)

    return Response(
        ApiKeyCreatedResponseSerializer(
            {
                "id": api_key.id,
                "name": api_key.name,
                "prefix": api_key.prefix,
                "api_key": raw_key,
                "created_at": api_key.created_at,
                "expires_at": api_key.expires_at,
            }
        ).data,
        status=status.HTTP_201_CREATED,
    )


@extend_schema(
    summary="Revoke an API key",
    tags=["API Keys"],
    responses={
        200: ApiKeyRevokeResponseSerializer,
        403: ErrorResponseSerializer,
        404: ErrorResponseSerializer,
    },
)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def revoke_api_key(request, key_id: int):
    if not api_keys_enabled():
        return _api_keys_disabled_response()

    if not revoke_api_key_for_user(request.user, key_id):
        return Response(
            ErrorResponseSerializer({"error": "API key not found"}).data,
            status=status.HTTP_404_NOT_FOUND,
        )

    return Response(ApiKeyRevokeResponseSerializer({"message": "API key revoked"}).data)
