"""drf-spectacular extensions for Lokdown OpenAPI schema generation."""

from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.plumbing import build_bearer_security_scheme_object

from lokdown.helpers.api_key_settings_helper import api_key_auth_header, api_key_auth_scheme


class LokdownApiKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "lokdown.authentication.LokdownApiKeyAuthentication"
    name = "lokdownApiKeyAuth"

    def get_security_definition(self, auto_schema):
        return build_bearer_security_scheme_object(
            header_name=api_key_auth_header(),
            token_prefix=api_key_auth_scheme(),
        )
