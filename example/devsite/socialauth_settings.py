"""Build SOCIALACCOUNT_PROVIDERS and enabled provider list from environment variables."""

from __future__ import annotations

import os


def _provider_app(client_id_env: str, secret_env: str) -> dict | None:
    client_id = os.environ.get(client_id_env, "").strip()
    secret = os.environ.get(secret_env, "").strip()
    if not client_id or not secret:
        return None
    return {"client_id": client_id, "secret": secret}


def build_socialaccount_providers() -> dict:
    providers = {}
    google = _provider_app("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")
    if google:
        providers["google"] = {"APPS": [google]}
    github = _provider_app("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET")
    if github:
        providers["github"] = {"APPS": [github], "VERIFIED_EMAIL": True}
    return providers


def build_enabled_social_providers() -> list[str]:
    return list(build_socialaccount_providers().keys())
