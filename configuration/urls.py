from django.contrib import admin
from django.http import HttpResponse
from drf_spectacular.utils import extend_schema
from drf_spectacular.views import SpectacularSwaggerView, SpectacularAPIView
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

from configuration.settings import VERSION
from lokdown.admin_url_override import override_admin_urls


@extend_schema(
    tags=["Authentication"],
    summary="Refresh JWT token",
    description="Takes a valid refresh token and returns a new access token.",
)
class TaggedTokenRefreshView(TokenRefreshView):
    pass

def index(request):
    # Adjust this URL to match the URL pattern for your Swagger documentation
    swagger_url = '/api/schema/swagger-ui/'  # This should be the URL where Swagger UI is served

    return HttpResponse(
        f'Penny Pusher (v{VERSION})<br><br>' f'<a href="{swagger_url}" target="_blank">Go to API Documentation</a>'
    )

urlpatterns = [
    path("", index, name="home"),
    # Django admin
    path('admin/', admin.site.urls),
    # Security app URLs (2FA and authentication)
    path('api/', include('lokdown.urls')),
    # api documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/schema/swagger-ui/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
]

# Override admin URLs with 2FA support if enabled
urlpatterns = override_admin_urls(urlpatterns)
