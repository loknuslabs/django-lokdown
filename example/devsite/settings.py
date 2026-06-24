"""Settings for the local example Django project (not part of the pip package)."""

from pathlib import Path
from django.core.management.utils import get_random_secret_key
import os
from datetime import timedelta

VERSION = "1.3.0"

# example/ directory
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("SECRET_KEY", get_random_secret_key())

DEBUG = True

ALLOWED_HOSTS = ["*"]

_DEFAULT_DEV_CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5173",
]
csrf_trusted_origins_env = os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", "")
if csrf_trusted_origins_env:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in csrf_trusted_origins_env.split(",") if o.strip()]
elif DEBUG:
    CSRF_TRUSTED_ORIGINS = _DEFAULT_DEV_CSRF_TRUSTED_ORIGINS
else:
    CSRF_TRUSTED_ORIGINS = []

CSRF_COOKIE_DOMAIN = os.getenv("DJANGO_CSRF_COOKIE_DOMAIN", "")

ADMINS = [("admin", "admin@example.com")]

from lokdown.socialauth.settings_helper import (  # noqa: E402
    LOKDOWN_ALLAUTH_BASE_APPS,
    get_allauth_recommended_settings,
    get_headless_frontend_urls,
    get_lokdown_socialauth_middleware,
    get_provider_installed_apps,
)

from devsite.socialauth_settings import (  # noqa: E402
    SOCIALAUTH_SUPPORTED_PROVIDERS,
    build_socialaccount_providers,
)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "lokdown",
    "tester",
    "corsheaders",
    "drf_spectacular",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    *LOKDOWN_ALLAUTH_BASE_APPS,
    *get_provider_installed_apps(["google", "github"]),
]

globals().update(get_allauth_recommended_settings())

SITE_ID = 1

SOCIALACCOUNT_PROVIDERS = build_socialaccount_providers()

LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS = SOCIALAUTH_SUPPORTED_PROVIDERS
LOKDOWN_SOCIALAUTH_CALLBACK_URL_NAME = "auth_callback"
LOGIN_REDIRECT_URL = "/auth/callback"

_spa_base_url = os.environ.get("LOKDOWN_SPA_BASE_URL", "http://localhost:5173").strip()
HEADLESS_FRONTEND_URLS = get_headless_frontend_urls(_spa_base_url)
LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS",
        f"{_spa_base_url},http://localhost:8000,http://127.0.0.1:8000",
    ).split(",")
    if origin.strip()
]

_auto_redirect = os.environ.get("SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER", "").strip()
if _auto_redirect:
    SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER = _auto_redirect

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    *get_lokdown_socialauth_middleware(),
]

CORS_ALLOW_ALL_ORIGINS = True

ROOT_URLCONF = "devsite.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "devsite.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

SECURE_SSL_REDIRECT = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 60
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_AGE = 1209600
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"

# Origins allowed when the SERVER verifies WebAuthn responses (py_webauthn).
# This does NOT set the browser rpId — that comes from the page URL hostname.
WEBAUTHN_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5173",
]
# Default rpId for dev; must match the hostname in your browser address bar.
# Use http://localhost:8000 for admin if passkeys were registered on localhost (not 127.0.0.1).
WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Lokdown Local")
WEBAUTHN_USE_REQUEST_HOST = os.environ.get("WEBAUTHN_USE_REQUEST_HOST", "False").lower() in (
    "true",
    "1",
    "yes",
)

BACKUP_CODE_RATE_LIMIT = int(os.environ.get("BACKUP_CODE_RATE_LIMIT", "10"))
TWOFA_SESSION_TIMEOUT = int(os.environ.get("TWOFA_SESSION_TIMEOUT", "10"))
BACKUP_CODES_COUNT = int(os.environ.get("BACKUP_CODES_COUNT", "8"))
BACKUP_CODE_LENGTH = int(os.environ.get("BACKUP_CODE_LENGTH", "10"))
ADMIN_2FA_REQUIRED = os.environ.get("ADMIN_2FA_REQUIRED", "True").lower() in (
    "true",
    "1",
    "yes",
)

STATIC_ROOT = BASE_DIR / "staticfiles"
STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_FORMAT_SUFFIXES": ["json"],
    "DEFAULT_VERSIONING_CLASS": None,
    "URL_FORMAT_OVERRIDE": None,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/hour",
        "user": "1000/hour",
    },
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "lokdown.authentication.LokdownApiKeyAuthentication",
    ],
}

# Lokdown feature flags (example project enables all capabilities)
LOKDOWN_TOTP_ENABLED = os.environ.get("LOKDOWN_TOTP_ENABLED", "true").lower() == "true"
LOKDOWN_PASSKEY_ENABLED = os.environ.get("LOKDOWN_PASSKEY_ENABLED", "true").lower() == "true"
LOKDOWN_SOCIALAUTH_ENABLED = os.environ.get("LOKDOWN_SOCIALAUTH_ENABLED", "true").lower() == "true"
LOKDOWN_API_KEYS_ENABLED = os.environ.get("LOKDOWN_API_KEYS_ENABLED", "true").lower() == "true"
LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS = int(os.environ.get("LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS", "365"))
LOKDOWN_API_KEY_ALLOW_INDEFINITE = os.environ.get("LOKDOWN_API_KEY_ALLOW_INDEFINITE", "true").lower() == "true"

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=5),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Django Lokdown",
    "VERSION": VERSION,
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "CAMELIZE_NAMES": False,
    "SORT_OPERATIONS": False,
    "SORT_TAGS": True,
    "DISABLE_ERRORS_AND_WARNINGS": True,
    "CONTACT": {
        "name": "Loknus Labs LLC",
        "email": "loknuslabs@gmail.com",
        "url": "https://loknuslabs.io",
    },
    "LICENSE": {
        "name": "GNU General Public License v3.0",
        "url": "https://www.gnu.org/licenses/gpl-3.0.html",
    },
    "AUTHENTICATION_SCHEMES": [
        {
            "name": "Basic Auth",
            "type": "http",
            "scheme": "basic",
        },
    ],
}
