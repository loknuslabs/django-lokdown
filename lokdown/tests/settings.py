"""Minimal Django settings for lokdown unit and integration tests."""

from datetime import timedelta

SECRET_KEY = "lokdown-test-secret-key-not-for-production"
DEBUG = True
ALLOWED_HOSTS = ["*", "testserver", "localhost"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.headless",
    "allauth.socialaccount.providers.dummy",
    "allauth.socialaccount.providers.google",
    "lokdown",
]

SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

SOCIALACCOUNT_ADAPTER = "lokdown.socialauth.adapters.CustomSocialAccountAdapter"

SOCIALACCOUNT_PROVIDERS = {
    "dummy": {},
    "google": {
        "APPS": [
            {
                "client_id": "test-google-client-id",
                "secret": "test-google-secret",
            },
        ],
    },
}

LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS = ["dummy", "google"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "lokdown.socialauth.middleware.RedirectAuthenticatedSocialLoginMiddleware",
    "lokdown.socialauth.middleware.AutoRedirectAccountLoginToSocialMiddleware",
]

ROOT_URLCONF = "lokdown.tests.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

AUTH_PASSWORD_VALIDATORS: list = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

WEBAUTHN_RP_ID = "localhost"
WEBAUTHN_RP_NAME = "Lokdown Test"
WEBAUTHN_ORIGINS = ["http://testserver"]
WEBAUTHN_ORIGIN = "http://testserver"

TWOFA_SESSION_TIMEOUT = 10
BACKUP_CODE_RATE_LIMIT = 10
BACKUP_CODES_COUNT = 4
BACKUP_CODE_LENGTH = 8
ADMIN_2FA_REQUIRED = True

LOKDOWN_PASSKEY_ENABLED = True
LOKDOWN_TOTP_ENABLED = True
LOKDOWN_SOCIALAUTH_ENABLED = True
LOKDOWN_API_KEYS_ENABLED = True
LOKDOWN_API_KEY_MAX_LIFESPAN_DAYS = 365
LOKDOWN_API_KEY_ALLOW_INDEFINITE = True

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "lokdown.authentication.LokdownApiKeyAuthentication",
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

LOKDOWN_SOCIALAUTH_CALLBACK_URL_NAME = "auth_callback"
LOKDOWN_SOCIALAUTH_ALLOWED_CALLBACK_ORIGINS = [
    "http://localhost:5173",
    "http://testserver",
]

HEADLESS_ONLY = True
CSRF_TRUSTED_ORIGINS = ["http://testserver", "http://localhost:5173"]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ],
        },
    },
]
