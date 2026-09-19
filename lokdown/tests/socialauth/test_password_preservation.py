import pytest
from django.contrib.auth.models import User

from lokdown.socialauth.password_preservation import (
    clear_stashed_passwords,
    restore_password_if_wiped,
    stash_usable_password,
)


@pytest.mark.django_db
class TestPasswordPreservation:
    def test_stashed_password_survives_set_unusable_password(self):
        user = User.objects.create_user(username="keepme", password="keeppass123")
        stash_usable_password(user)

        user.set_unusable_password()
        user.save(update_fields=["password"])

        user.refresh_from_db()
        assert user.has_usable_password()
        assert user.check_password("keeppass123")

    def test_unstashed_user_can_still_have_password_cleared(self):
        user = User.objects.create_user(username="clearme", password="clearpass123")

        user.set_unusable_password()
        user.save(update_fields=["password"])

        user.refresh_from_db()
        assert not user.has_usable_password()

    def test_does_not_stash_unusable_password(self):
        user = User.objects.create_user(username="socialonly", password="unused")
        user.set_unusable_password()
        user.save(update_fields=["password"])
        clear_stashed_passwords()

        stash_usable_password(user)
        restore_password_if_wiped(User, user)
        assert not user.has_usable_password()

    def test_stash_ignores_unsaved_user(self):
        user = User(username="new")
        user.set_unusable_password()
        stash_usable_password(user)
        restore_password_if_wiped(User, user)
        assert not user.has_usable_password()

    def test_module_does_not_import_allauth(self):
        import ast
        from pathlib import Path

        import lokdown.socialauth.password_preservation as preservation

        tree = ast.parse(Path(preservation.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not alias.name.startswith("allauth") for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("allauth")
