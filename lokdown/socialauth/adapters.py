from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

from lokdown.helpers.feature_settings_helper import public_registration_enabled


class CustomAccountAdapter(DefaultAccountAdapter):
    """Gate email/password signup via LOKDOWN_ALLOW_PUBLIC_REGISTRATION."""

    def is_open_for_signup(self, request):
        return public_registration_enabled()


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Set username from email when creating a user via social signup (e.g. Google)."""

    def is_open_for_signup(self, request, sociallogin):
        return public_registration_enabled()

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        email = user.email or data.get("email") or ""
        if email:
            from django.contrib.auth import get_user_model

            User = get_user_model()
            base_username = email[:150]
            username = base_username
            n = 0
            while User.objects.filter(username=username).exists():
                n += 1
                suffix = f"_{n}"
                username = base_username[: 150 - len(suffix)] + suffix
            user.username = username
        return user
