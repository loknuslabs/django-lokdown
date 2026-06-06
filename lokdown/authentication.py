"""DRF authentication for lokdown user API keys."""

from __future__ import annotations

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from lokdown.helpers.api_key_helper import authenticate_api_key
from lokdown.helpers.api_key_settings_helper import (
    api_key_auth_header,
    api_key_auth_scheme,
    api_keys_enabled,
)


class LokdownApiKeyAuthentication(BaseAuthentication):
    """
    Authenticate requests with ``Authorization: Api-Key <key>`` (configurable).

    Add to ``REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`` alongside JWT.
    API keys identify the owning user but do not replace password login flows.
    """

    def authenticate(self, request):
        if not api_keys_enabled():
            return None

        raw_key = self._extract_key(request)
        if not raw_key:
            return None

        user = authenticate_api_key(raw_key)
        if user is None:
            raise AuthenticationFailed("Invalid or expired API key")

        return user, None

    def _extract_key(self, request) -> str | None:
        header_name = api_key_auth_header()
        meta_key = f"HTTP_{header_name.upper().replace('-', '_')}"
        auth = request.META.get(meta_key, "")
        if not auth:
            return None

        keyword = api_key_auth_scheme()
        parts = auth.split()
        if len(parts) != 2 or parts[0] != keyword:
            return None
        return parts[1]
