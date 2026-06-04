from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Set username from email when creating a user via social signup (e.g. Google)."""

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
