from django.contrib import admin
from drf_spectacular.utils import extend_schema
from drf_spectacular.views import SpectacularSwaggerView, SpectacularAPIView
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from lokdown.admin_url_override import override_admin_urls
from lokdown.control.token_views import CustomTokenObtainPairView


@extend_schema(
    tags=["Authentication"],
    summary="Refresh JWT token",
    description="Takes a valid refresh token and returns a new access token.",
)
class TaggedTokenRefreshView(TokenRefreshView):
    pass


urlpatterns = [
    # Django admin
    path('admin/', admin.site.urls),
    # Legacy token endpoints (kept for backward compatibility)
    path('api/token', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh', TaggedTokenRefreshView.as_view(), name='token_refresh'),
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
