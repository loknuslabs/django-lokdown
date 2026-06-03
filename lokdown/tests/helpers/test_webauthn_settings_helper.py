import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory

from lokdown.helpers.webauthn_settings_helper import (
    get_webauthn_expected_origin,
    parse_webauthn_origins,
    resolve_rp_id,
)


@pytest.mark.django_db
class TestWebauthnSettingsHelper:
    def test_parse_webauthn_origins_list(self, settings):
        settings.WEBAUTHN_ORIGINS = ["http://a.test", "http://b.test"]
        settings.WEBAUTHN_ORIGIN = "http://legacy.test"
        assert parse_webauthn_origins() == [
            "http://a.test",
            "http://b.test",
            "http://legacy.test",
        ]

    def test_get_webauthn_expected_origin_multiple(self, settings):
        settings.WEBAUTHN_ORIGINS = ["http://a.test", "http://b.test"]
        settings.WEBAUTHN_ORIGIN = ""
        assert get_webauthn_expected_origin() == ["http://a.test", "http://b.test"]

    def test_get_webauthn_expected_origin_dev_fallback(self, settings):
        settings.DEBUG = True
        settings.WEBAUTHN_ORIGINS = []
        settings.WEBAUTHN_ORIGIN = ""
        assert get_webauthn_expected_origin() == "http://localhost:8000"

    def test_get_webauthn_expected_origin_fails_closed_in_production(self, settings):
        settings.DEBUG = False
        settings.WEBAUTHN_ORIGINS = []
        settings.WEBAUTHN_ORIGIN = ""
        with pytest.raises(ImproperlyConfigured, match="WEBAUTHN_ORIGINS"):
            get_webauthn_expected_origin()

    def test_resolve_rp_id_from_origin_header(self, settings):
        settings.WEBAUTHN_RP_ID = "localhost"
        request = RequestFactory().get(
            "/",
            HTTP_HOST="127.0.0.1:8000",
            HTTP_ORIGIN="http://localhost:5173",
        )
        assert resolve_rp_id(request) == "localhost"

    def test_resolve_rp_id_uses_browser_header(self, settings):
        settings.WEBAUTHN_RP_ID = "localhost"
        request = RequestFactory().get(
            "/",
            HTTP_HOST="127.0.0.1:8000",
            HTTP_X_LOKDOWN_RP_ID="localhost",
        )
        assert resolve_rp_id(request) == "localhost"

    def test_resolve_rp_id_uses_request_host_for_local_dev_without_origin(self, settings):
        settings.WEBAUTHN_RP_ID = "localhost"
        request = RequestFactory().get("/", HTTP_HOST="127.0.0.1:8000")
        assert resolve_rp_id(request) == "127.0.0.1"

    def test_resolve_rp_id_fallback(self, settings):
        settings.WEBAUTHN_RP_ID = "localhost"
        assert resolve_rp_id(None) == "localhost"

    def test_resolve_rp_id_ignores_untrusted_host(self, settings):
        settings.WEBAUTHN_RP_ID = "app.example.com"
        request = RequestFactory().get("/", HTTP_HOST="evil.example.com")
        assert resolve_rp_id(request) == "app.example.com"
