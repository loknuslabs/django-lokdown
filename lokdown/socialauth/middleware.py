"""django-allauth middleware for SPA-friendly social login flows."""

from __future__ import annotations

from urllib.parse import urlencode

from django.conf import settings
from django.shortcuts import redirect
from django.urls import NoReverseMatch, reverse

from allauth.account.utils import get_next_redirect_url
from allauth.socialaccount.providers.base.constants import AuthProcess

from lokdown.socialauth.settings_helper import (
    get_auto_redirect_provider,
    get_enabled_social_providers,
    get_social_login_url_name,
    social_login_path_prefix,
)


def _account_login_path() -> str:
    prefix = getattr(settings, "LOKDOWN_SOCIALAUTH_ACCOUNT_URL_PREFIX", "accounts").strip("/")
    return f"/{prefix}/login"


def _social_callback_url_name() -> str:
    return getattr(settings, "LOKDOWN_SOCIALAUTH_CALLBACK_URL_NAME", "auth_callback")


class RedirectAuthenticatedSocialLoginMiddleware:
    """
    Avoid sending already-signed-in users through OAuth again when they open
    ``/accounts/<provider>/login/?next=...`` (e.g. SPA retry). Send them to ``?next=``
    or the configured JWT callback. Skips when ``process=connect`` (linking accounts).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        login_prefixes = tuple(social_login_path_prefix(provider_id) for provider_id in get_enabled_social_providers())
        if (
            request.user.is_authenticated
            and request.GET.get("process") != AuthProcess.CONNECT
            and any(request.path.startswith(prefix) for prefix in login_prefixes)
        ):
            nxt = get_next_redirect_url(request)
            if nxt:
                return redirect(nxt)
            try:
                return redirect(reverse(_social_callback_url_name()))
            except NoReverseMatch:
                return self.get_response(request)
        return self.get_response(request)


class AutoRedirectAccountLoginToSocialMiddleware:
    """
    Skip the account login screen and send users straight to a social provider.

    Preserves ``?next=`` (e.g. ``/auth/callback``). Opt out:
    ``GET /accounts/login/?local=1`` (email/password form).

    Enable with ``SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER = "google"`` (or legacy
    ``SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_GOOGLE = True``).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        provider_id = get_auto_redirect_provider()
        if not provider_id:
            return self.get_response(request)
        if request.method != "GET" or request.user.is_authenticated:
            return self.get_response(request)
        path = request.path.rstrip("/")
        if path != _account_login_path().rstrip("/"):
            return self.get_response(request)
        if request.GET.get("local") or request.GET.get("password") or request.GET.get("email"):
            return self.get_response(request)
        try:
            social_url = reverse(get_social_login_url_name(provider_id))
        except NoReverseMatch:
            return self.get_response(request)
        q = {k: v for k, v in request.GET.items() if k in ("next", "process")}
        if q:
            social_url = f"{social_url}?{urlencode(q)}"
        return redirect(social_url)
