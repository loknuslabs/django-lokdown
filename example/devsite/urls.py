from django.contrib import admin
from django.http import HttpResponse
from drf_spectacular.utils import extend_schema
from drf_spectacular.views import SpectacularSwaggerView, SpectacularAPIView
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView

from devsite.settings import VERSION
from lokdown.urls import override_admin_urls


@extend_schema(
    tags=["Authentication"],
    summary="Refresh JWT token",
    description="Takes a valid refresh token and returns a new access token.",
)
class TaggedTokenRefreshView(TokenRefreshView):
    pass


def index(request):
    swagger_url = "/api/schema/swagger-ui/"
    return HttpResponse(
        f"Django Lokdown example (v{VERSION})<br><br>"
        f'<a href="{swagger_url}" target="_blank">Go to API Documentation</a>'
    )


urlpatterns = [
    path("", index, name="home"),
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
