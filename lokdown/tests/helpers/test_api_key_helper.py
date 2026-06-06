import pytest
from datetime import timedelta
from django.utils import timezone

from lokdown.helpers.api_key_helper import (
    authenticate_api_key,
    create_user_api_key,
    is_api_key_active,
    list_user_api_keys,
    revoke_api_key,
    validate_requested_expires_at,
)
from lokdown.models import UserApiKey


@pytest.mark.django_db
class TestApiKeyHelper:
    def test_create_and_authenticate(self, user):
        api_key, raw = create_user_api_key(user, name="test key")
        assert raw.startswith("lk_")
        assert api_key.key_hash != raw
        assert authenticate_api_key(raw) == user

    def test_list_excludes_revoked(self, user):
        api_key, _raw = create_user_api_key(user)
        assert len(list_user_api_keys(user)) == 1
        revoke_api_key(user, api_key.id)
        assert list_user_api_keys(user) == []

    def test_cannot_revoke_other_users_key(self, user, other_user):
        api_key, _raw = create_user_api_key(other_user)
        assert revoke_api_key(user, api_key.id) is False
        assert list_user_api_keys(other_user) == [api_key]

    def test_staff_can_revoke_other_users_key(self, user, other_user):
        api_key, _raw = create_user_api_key(other_user)
        user.is_staff = True
        user.save(update_fields=["is_staff"])
        assert revoke_api_key(user, api_key.id) is True
        assert list_user_api_keys(other_user) == []

    def test_expired_key_rejected(self, user):
        expires = timezone.now() + timedelta(days=1)
        _api_key, raw = create_user_api_key(user, expires_at=expires)
        UserApiKey.objects.filter(user=user).update(expires_at=timezone.now() - timedelta(minutes=1))
        assert authenticate_api_key(raw) is None

    def test_validate_indefinite_when_disabled(self, settings):
        settings.LOKDOWN_API_KEY_ALLOW_INDEFINITE = False
        with pytest.raises(ValueError, match="Indefinite"):
            validate_requested_expires_at(None)

    def test_validate_max_lifespan(self, settings):
        settings.LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS = 30
        too_far = timezone.now() + timedelta(days=31)
        with pytest.raises(ValueError, match="maximum lifespan"):
            validate_requested_expires_at(too_far)

    def test_is_api_key_active(self, user):
        api_key, _raw = create_user_api_key(user)
        assert is_api_key_active(api_key) is True
        revoke_api_key(user, api_key.id)
        api_key.refresh_from_db()
        assert is_api_key_active(api_key) is False
