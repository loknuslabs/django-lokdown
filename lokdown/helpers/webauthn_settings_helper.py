"""WebAuthn settings helpers (multi-origin, request-aware rpId)."""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest


def parse_webauthn_origins() -> list[str]:
    """
    Return allowed WebAuthn origins from settings.

    Supports:
    - ``WEBAUTHN_ORIGINS`` (list or comma-separated string)
    - ``WEBAUTHN_ORIGIN`` (string or list, for backwards compatibility)
    """
    origins: list[str] = []

    configured = getattr(settings, "WEBAUTHN_ORIGINS", None)
    if configured:
        if isinstance(configured, str):
            origins.extend(o.strip() for o in configured.split(",") if o.strip())
        else:
            origins.extend(str(o).strip() for o in configured if str(o).strip())

    legacy = getattr(settings, "WEBAUTHN_ORIGIN", None)
    if legacy:
        if isinstance(legacy, str):
            if "," in legacy:
                origins.extend(o.strip() for o in legacy.split(",") if o.strip())
            else:
                origins.append(legacy.strip())
        else:
            origins.extend(str(o).strip() for o in legacy if str(o).strip())

    seen: set[str] = set()
    unique: list[str] = []
    for origin in origins:
        if origin not in seen:
            seen.add(origin)
            unique.append(origin)
    return unique


def get_webauthn_expected_origin():
    """Value for py_webauthn ``expected_origin`` (str or list)."""
    origins = parse_webauthn_origins()
    if not origins:
        return "http://localhost:8000"
    if len(origins) == 1:
        return origins[0]
    return origins


def resolve_rp_id(request: HttpRequest | None = None) -> str:
    """
    Relying party ID for the current ceremony.

    Uses the request hostname when available so admin works on both
    ``localhost`` and ``127.0.0.1`` without a browser "invalid domain" error.
    Falls back to ``WEBAUTHN_RP_ID``.
    """
    if request is not None:
        host = request.get_host().split(":")[0].strip()
        if host:
            return host
    return getattr(settings, "WEBAUTHN_RP_ID", "localhost")
