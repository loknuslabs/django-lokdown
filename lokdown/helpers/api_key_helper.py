"""Create, verify, and manage user-tied API keys."""

from __future__ import annotations

import secrets
from datetime import datetime

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from lokdown.helpers.api_key_settings_helper import (
    api_key_prefix,
    api_keys_allow_indefinite,
    api_keys_enabled,
    max_allowed_expires_at,
)
from lokdown.models import UserApiKey


def _require_api_keys_enabled() -> None:
    if not api_keys_enabled():
        raise ImproperlyConfigured("LOKDOWN_API_KEYS_ENABLED is False")


def hash_api_key(raw_key: str) -> str:
    return make_password(raw_key)


def verify_api_key_hash(raw_key: str, stored_hash: str) -> bool:
    return check_password(raw_key, stored_hash)


def _generate_raw_key() -> tuple[str, str]:
    """Return ``(full_key, lookup_prefix)``."""
    prefix = api_key_prefix()
    lookup = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    full_key = f"{prefix}{lookup}.{secret}"
    lookup_prefix = f"{prefix}{lookup}"
    return full_key, lookup_prefix


def validate_requested_expires_at(expires_at: datetime | None) -> datetime | None:
    """Validate expiry against settings; return normalized ``expires_at``."""
    if expires_at is None:
        if not api_keys_allow_indefinite():
            raise ValueError("Indefinite API key lifespans are disabled")
        return None

    now = timezone.now()
    if expires_at <= now:
        raise ValueError("Expiry must be in the future")

    max_expires = max_allowed_expires_at(now)
    if max_expires is not None and expires_at > max_expires:
        raise ValueError("Expiry exceeds the configured maximum lifespan")

    return expires_at


@transaction.atomic
def create_user_api_key(
    user: User,
    *,
    name: str = "",
    expires_at: datetime | None = None,
) -> tuple[UserApiKey, str]:
    """
    Create an API key for ``user``.

    Returns ``(model, plaintext_key)``. The plaintext key is shown once.
    """
    _require_api_keys_enabled()
    expires_at = validate_requested_expires_at(expires_at)

    raw_key, lookup_prefix = _generate_raw_key()
    api_key = UserApiKey.objects.create(
        user=user,
        name=name.strip(),
        prefix=lookup_prefix,
        key_hash=hash_api_key(raw_key),
        expires_at=expires_at,
    )
    return api_key, raw_key


def list_user_api_keys(user: User) -> list[UserApiKey]:
    return list(UserApiKey.objects.filter(user=user, revoked_at__isnull=True).order_by("-created_at"))


def revoke_api_key(actor: User, key_id: int) -> bool:
    """
    Revoke an API key by id.

    Non-staff users may revoke only their own keys. Staff users may revoke any key.
    """
    queryset = UserApiKey.objects.filter(pk=key_id, revoked_at__isnull=True)
    if not actor.is_staff:
        queryset = queryset.filter(user=actor)
    updated = queryset.update(revoked_at=timezone.now())
    return updated > 0


def is_api_key_active(api_key: UserApiKey) -> bool:
    if api_key.revoked_at is not None:
        return False
    if api_key.expires_at is not None and api_key.expires_at <= timezone.now():
        return False
    return True


def authenticate_api_key(raw_key: str) -> User | None:
    """
    Resolve a raw API key to its owning user.

    Returns ``None`` when the key is invalid, expired, revoked, or API keys are disabled.
    """
    if not api_keys_enabled() or not raw_key:
        return None

    prefix = api_key_prefix()
    if not raw_key.startswith(prefix):
        return None

    lookup_prefix, _, _secret = raw_key.partition(".")
    if not lookup_prefix or lookup_prefix == raw_key:
        return None

    try:
        api_key = UserApiKey.objects.select_related("user").get(prefix=lookup_prefix, revoked_at__isnull=True)
    except UserApiKey.DoesNotExist:
        return None

    if not verify_api_key_hash(raw_key, api_key.key_hash):
        return None
    if not is_api_key_active(api_key):
        return None

    UserApiKey.objects.filter(pk=api_key.pk).update(last_used_at=timezone.now())
    return api_key.user
