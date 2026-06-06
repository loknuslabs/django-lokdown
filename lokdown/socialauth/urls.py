"""URL helpers for mounting django-allauth in the host project."""

from django.urls import include, path


def get_allauth_urlpatterns(
    url_prefix: str = "accounts/",
    headless_url_prefix: str = "_allauth/",
):
    """
    URL patterns for allauth account callbacks and headless API routes.

    With ``HEADLESS_ONLY = True``, ``/accounts/*`` serves OAuth provider callbacks
    only; the SPA uses ``/_allauth/browser/v1/*`` for login and provider discovery.

    Example::

        urlpatterns = [
            *get_allauth_urlpatterns(),
            path("api/", include("lokdown.urls")),
        ]
    """
    return [
        path(url_prefix, include("allauth.urls")),
        path(headless_url_prefix, include("allauth.headless.urls")),
    ]
