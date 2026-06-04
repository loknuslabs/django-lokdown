"""URL helpers for mounting django-allauth in the host project."""

from django.urls import include, path


def get_allauth_urlpatterns(url_prefix: str = "accounts/"):
    """
    URL patterns for ``path("<prefix>", include(...))``.

    Example::

        urlpatterns = [
            *get_allauth_urlpatterns(),
            path("api/", include("lokdown.urls")),
        ]
    """
    return [path(url_prefix, include("allauth.urls"))]
