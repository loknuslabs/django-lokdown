from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path, reverse
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from devsite.auth_views import auth_callback
from devsite.settings import VERSION, _SOCIAL_PROVIDER_IDS
from lokdown.socialauth.urls import get_allauth_urlpatterns
from lokdown.urls import override_admin_urls


def index(request):
    swagger_url = "/api/schema/swagger-ui/"
    lines = [
        f"Django Lokdown example (v{VERSION})<br><br>",
        f'<a href="{swagger_url}" target="_blank">API documentation</a><br>',
        '<a href="/accounts/login/">Account login (allauth)</a><br>',
    ]
    callback_url = reverse("auth_callback")
    for provider in _SOCIAL_PROVIDER_IDS:
        login_url = reverse(f"{provider}_login")
        lines.append(f'<a href="{login_url}?next={callback_url}">Sign in with {provider.title()}</a><br>')
    if not _SOCIAL_PROVIDER_IDS:
        lines.append(
            "<p><em>OAuth: set GOOGLE_CLIENT_ID/SECRET and/or GITHUB_CLIENT_ID/SECRET "
            "(see example/.env.example), then restart the server.</em></p>"
        )
    return HttpResponse("".join(lines))


urlpatterns = [
    path("", index, name="home"),
    *get_allauth_urlpatterns(),
    path("auth/callback", auth_callback, name="auth_callback"),
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
