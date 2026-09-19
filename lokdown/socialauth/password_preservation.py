"""Prevent social login from deleting an existing usable password.

allauth's ``SOCIALACCOUNT_EMAIL_AUTHENTICATION`` flow calls ``wipe_password()``
when the matched local email is missing or unverified. Lokdown keeps both
password and social login available by stashing the hash at social-login start
and restoring it if a save would make the password unusable.
"""

from __future__ import annotations

from threading import local

from django.contrib.auth.base_user import AbstractBaseUser
from django.core.signals import request_finished
from django.db.models.signals import pre_save

_state = local()


def stash_usable_password(user: AbstractBaseUser | None) -> None:
    """Remember a usable password hash for ``user`` for the rest of this request."""
    if user is None or not getattr(user, "pk", None):
        return
    if not user.has_usable_password():
        return
    passwords = getattr(_state, "passwords", None)
    if passwords is None:
        passwords = {}
        _state.passwords = passwords
    passwords[user.pk] = user.password


def clear_stashed_passwords(**kwargs) -> None:
    if hasattr(_state, "passwords"):
        del _state.passwords


def restore_password_if_wiped(sender, instance, **kwargs) -> None:
    """Undo ``set_unusable_password()`` for users stashed during social login."""
    passwords = getattr(_state, "passwords", None)
    if not passwords or instance.pk not in passwords:
        return
    if instance.has_usable_password():
        return
    instance.password = passwords[instance.pk]


def connect_signals() -> None:
    """Register preservation signals. Safe to call more than once; no allauth import."""
    from django.contrib.auth import get_user_model

    pre_save.connect(
        restore_password_if_wiped,
        sender=get_user_model(),
        dispatch_uid="lokdown.socialauth.preserve_password",
    )
    request_finished.connect(
        clear_stashed_passwords,
        dispatch_uid="lokdown.socialauth.clear_stashed_passwords",
    )
