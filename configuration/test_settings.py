from configuration.settings import *  # Import base settings

REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] = ['rest_framework.authentication.SessionAuthentication']

SECURE_SSL_REDIRECT = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

SCHEDULER_AUTOSTART = False
