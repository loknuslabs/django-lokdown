import pytest
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

    def test_resolve_rp_id_from_request(self, settings):
        settings.WEBAUTHN_RP_ID = "localhost"
        request = RequestFactory().get("/", HTTP_HOST="127.0.0.1:8000")
        assert resolve_rp_id(request) == "127.0.0.1"

    def test_resolve_rp_id_fallback(self, settings):
        settings.WEBAUTHN_RP_ID = "localhost"
        assert resolve_rp_id(None) == "localhost"
