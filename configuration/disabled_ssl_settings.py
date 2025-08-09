from configuration.settings import *  # Import base settings

DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')

SECURE_SSL_REDIRECT = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
