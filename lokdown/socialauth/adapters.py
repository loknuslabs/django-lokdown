from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.models import EmailAddress
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

from lokdown.helpers.feature_settings_helper import public_registration_enabled
from lokdown.socialauth.password_preservation import stash_usable_password


class CustomAccountAdapter(DefaultAccountAdapter):
    """Gate email/password signup via LOKDOWN_ALLOW_PUBLIC_REGISTRATION."""

    def is_open_for_signup(self, request):
        return public_registration_enabled()


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Set username from email when creating a user via social signup (e.g. Google)."""

    def is_open_for_signup(self, request, sociallogin):
        return public_registration_enabled()

    def pre_social_login(self, request, sociallogin):
        super().pre_social_login(request, sociallogin)
        stash_usable_password(getattr(sociallogin, "user", None))
        if request is not None:
            request_user = getattr(request, "user", None)
            if request_user is not None and getattr(request_user, "is_authenticated", False):
                stash_usable_password(request_user)
        self._ensure_verified_email_for_social_email_auth(sociallogin)

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

    def _ensure_verified_email_for_social_email_auth(self, sociallogin):
        """Record the provider-verified email so allauth skips ``wipe_password()``.

        Password hashes are also stashed in ``pre_social_login`` so a wipe cannot
        persist even if this email row is missing.
        """
        email = getattr(sociallogin, "_did_authenticate_by_email", None)
        user = getattr(sociallogin, "user", None)
        if not email or user is None or not getattr(user, "pk", None):
            return

        try:
            address = EmailAddress.objects.get_for_user(user, email)
        except EmailAddress.DoesNotExist:
            has_primary = EmailAddress.objects.filter(user=user, primary=True).exists()
            EmailAddress.objects.create(
                user=user,
                email=email,
                verified=True,
                primary=not has_primary,
            )
            return

        if not address.verified:
            address.verified = True
            address.save(update_fields=["verified"])
