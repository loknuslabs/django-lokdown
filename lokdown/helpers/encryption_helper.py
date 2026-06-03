"""Fernet encryption for sensitive values stored at rest."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from hashlib import sha256

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

FERNET_TOKEN_PREFIX = "gAAAAA"


def _fernet_key_bytes() -> bytes:
    configured = getattr(settings, "LOKDOWN_FERNET_KEY", None)
    if configured:
        return configured.encode() if isinstance(configured, str) else configured
    return urlsafe_b64encode(sha256(settings.SECRET_KEY.encode()).digest())


def _fernet() -> Fernet:
    return Fernet(_fernet_key_bytes())


def is_encrypted_value(value: str) -> bool:
    return bool(value and value.startswith(FERNET_TOKEN_PREFIX))


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    if is_encrypted_value(plaintext):
        return plaintext
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    if not is_encrypted_value(ciphertext):
        return ciphertext
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt lokdown secret value") from exc
