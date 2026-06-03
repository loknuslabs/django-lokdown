"""WebAuthn settings helpers (multi-origin, request-aware rpId)."""

from __future__ import annotations

from urllib.parse import urlparse

from django.conf import settings
from django.http import HttpRequest

_DEV_RP_ID_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})

# IPv6 loopback only — [::1] pages use the same rpId as localhost.
_DEV_RP_ID_CANONICAL = {
    "[::1]": "localhost",
}


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


def normalize_dev_rp_id(host: str | None) -> str | None:
    """Map IPv6/IPv4 loopback hosts to a single dev rpId (default WEBAUTHN_RP_ID)."""
    if not host:
        return None
    host = host.strip().lower().split(":")[0]
    configured = getattr(settings, "WEBAUTHN_RP_ID", "localhost")
    if host in _DEV_RP_ID_CANONICAL:
        return _DEV_RP_ID_CANONICAL[host]
    return host


def _browser_rp_id_header(request: HttpRequest) -> str | None:
    """rpId reported by admin/SPA JavaScript (``X-Lokdown-Rp-Id``)."""
    return normalize_dev_rp_id(request.META.get("HTTP_X_LOKDOWN_RP_ID"))


def _hostname_from_origin_header(request: HttpRequest) -> str | None:
    """
    Derive rpId from the browser origin when the SPA calls the API cross-port.

    ``127.0.0.1`` and ``localhost`` are different WebAuthn rpIds; the API server's
    Host header must not override the page the user is on.
    """
    origin = request.META.get("HTTP_ORIGIN")
    if not origin:
        referer = request.META.get("HTTP_REFERER")
        if referer:
            origin = referer
        else:
            return None
    parsed = urlparse(origin)
    return normalize_dev_rp_id(parsed.hostname)


def resolve_rp_id(request: HttpRequest | None = None) -> str:
    """
    Relying party ID for the current ceremony.

    Priority:
    1. ``X-Lokdown-Rp-Id`` header (admin template sends ``window.location.hostname``)
    2. Hostname from ``Origin`` / ``Referer`` (cross-origin SPA)
    3. Request ``Host`` for local dev hosts (normalized to ``WEBAUTHN_RP_ID`` when applicable)
    4. ``WEBAUTHN_RP_ID`` for production

    Note: ``WEBAUTHN_ORIGINS`` is only used for server-side origin checks, not this rpId.
    """
    configured = getattr(settings, "WEBAUTHN_RP_ID", "localhost")
    if request is None:
        return configured

    browser_rp = _browser_rp_id_header(request)
    if browser_rp:
        return browser_rp

    origin_host = _hostname_from_origin_header(request)
    if origin_host:
        return origin_host

    host = normalize_dev_rp_id(request.get_host().split(":")[0])
    if host and host in _DEV_RP_ID_HOSTS:
        return host

    return configured
