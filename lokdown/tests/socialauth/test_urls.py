from lokdown.socialauth.urls import get_allauth_urlpatterns


class TestAllauthUrls:
    def test_get_allauth_urlpatterns_default_prefix(self):
        patterns = get_allauth_urlpatterns()
        assert len(patterns) == 1
        assert str(patterns[0].pattern) == "accounts/"

    def test_get_allauth_urlpatterns_custom_prefix(self):
        patterns = get_allauth_urlpatterns("sso/")
        assert str(patterns[0].pattern) == "sso/"
