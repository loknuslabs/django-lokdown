from lokdown import socialauth
from lokdown.socialauth.adapters import CustomSocialAccountAdapter as AdapterDirect


class TestPackageExports:
    def test_lazy_adapter_import(self):
        assert socialauth.CustomSocialAccountAdapter is AdapterDirect

    def test_backward_compatible_middleware_aliases(self):
        assert (
            socialauth.RedirectAuthenticatedGoogleLoginMiddleware
            is socialauth.RedirectAuthenticatedSocialLoginMiddleware
        )
        assert (
            socialauth.AutoRedirectAccountLoginToGoogleMiddleware
            is socialauth.AutoRedirectAccountLoginToSocialMiddleware
        )

    def test_settings_helper_imported_eagerly(self):
        assert socialauth.get_enabled_social_providers is not None

    def test_public_all_exports(self):
        assert "CustomSocialAccountAdapter" in socialauth.__all__
        assert "get_allauth_recommended_settings" in socialauth.__all__
