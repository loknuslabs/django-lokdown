from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path

from lokdown.socialauth.urls import get_allauth_urlpatterns
from lokdown.urls import override_admin_urls


def auth_callback(request):
    return HttpResponse("ok", content_type="text/plain")


urlpatterns = [
    path("api/", include("lokdown.urls")),
    *get_allauth_urlpatterns(),
    path("auth/callback", auth_callback, name="auth_callback"),
    path("admin/", admin.site.urls),
]

urlpatterns = override_admin_urls(urlpatterns)
