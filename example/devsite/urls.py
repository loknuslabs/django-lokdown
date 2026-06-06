from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from devsite.auth_views import auth_callback
from devsite.settings import VERSION
from lokdown.socialauth.settings_helper import get_enabled_social_providers
from lokdown.socialauth.urls import get_allauth_urlpatterns
from lokdown.urls import override_admin_urls


def index(request):
    swagger_url = "/api/schema/swagger-ui/"
    lines = [
        f"Django Lokdown example (v{VERSION})<br><br>",
        f'<a href="{swagger_url}" target="_blank">API documentation</a><br>',
        '<a href="/_allauth/browser/v1/config">Allauth headless config (providers)</a><br>',
        '<a href="/api/auth/oauth/providers">Lokdown OAuth provider metadata</a><br>',
    ]
    provider_ids = get_enabled_social_providers()
    if not provider_ids:
        lines.append(
            "<p><em>OAuth: add Social applications in Django admin "
            "(<a href=\"/admin/socialaccount/socialapp/\">Social applications</a>) "
            "for Google and/or GitHub, linked to the current Site, then refresh.</em></p>"
        )
    else:
        lines.append(
            "<p><em>OAuth login is SPA-driven via allauth headless "
            "(POST to <code>/_allauth/browser/v1/auth/provider/redirect</code>). "
            "See API docs for the full flow.</em></p>"
        )
    return HttpResponse("".join(lines))


urlpatterns = [
    path("", index, name="home"),
    *get_allauth_urlpatterns(),
    path("auth/callback", auth_callback, name="auth_callback"),
    path("oauth/callback", auth_callback, name="oauth_callback"),
    path("admin/", admin.site.urls),
    path("api/", include("lokdown.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/schema/swagger-ui/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
]

urlpatterns = override_admin_urls(urlpatterns)
