# Django Lokdown

A reusable Django package providing Two-Factor Authentication (2FA) with TOTP, WebAuthn passkeys, JWT APIs, enhanced Django admin integration, and optional social login (django-allauth).

**Deep-dive authentication workflows:** [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Project structure](#project-structure)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [Password login and 2FA](#password-login-and-2fa)
- [Social login (OAuth)](#social-login-oauth)
- [Local development (example project)](#local-development-example-project)
- [Django admin](#django-admin)
- [Models](#models)
- [Management commands](#management-commands)
- [Customization](#customization)
- [Security](#security)
- [System checks](#system-checks)
- [Dependencies](#dependencies)
- [License, contributing, and support](#license-contributing-and-support)

---

## Overview

Django Lokdown supports two primary second-factor methods:

1. **TOTP** — compatible with Google Authenticator, Authy, and similar apps
2. **WebAuthn passkeys** — YubiKeys, Apple Keychain, Google Password Manager, Windows Hello, and other FIDO2/WebAuthn authenticators

Optional **social login** (Google, GitHub, etc.) via django-allauth can be added as a first-factor sign-in path alongside password + JWT APIs. OAuth helpers are documented in OpenAPI under `/api/auth/oauth/*`. Credentials are configured in Django admin (**Social applications**), not environment variables.

Lokdown works **without** allauth in `INSTALLED_APPS`; `python manage.py check` does not require it.

---

## Features

- **TOTP (Time-based One-Time Password)**: Compatible with authenticator apps
- **WebAuthn Passkeys**: Modern passwordless authentication
- **Backup Codes**: One-time use backup codes for account recovery
- **Rate Limiting**: Strict rate limiting for backup codes and failed attempts
- **JWT APIs**: Password login, 2FA verify, token refresh via DRF
- **Admin Dashboard**: Security monitoring with dark mode support
- **Admin 2FA**: Streamlined one-click TOTP/passkey setup and verification for staff
- **CLI Tools**: Security audit and management commands
- **Social login (django-allauth)**: SPA-friendly OAuth middleware, email-based usernames, OpenAPI-documented `/api/auth/oauth/*` helpers

---

## Installation

### Install in your Django project (PyPI)

```bash
pip install django-lokdown
```

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "lokdown",
]
```

```python
# urls.py
from django.urls import path, include
from lokdown.urls import override_admin_urls

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("lokdown.urls")),
]

urlpatterns = override_admin_urls(urlpatterns)
```

```bash
python manage.py migrate
```

Configure WebAuthn settings (see [Configuration](#configuration)). Optional OAuth: see [Social login](#social-login-oauth).

### Requirements

```txt
Django>=4.2.3
djangorestframework
djangorestframework-simplejwt
django-cors-headers
drf-spectacular
django-lokdown
pyotp
webauthn
qrcode
Pillow
```

---

## Project structure

```
django-lokdown/
├── lokdown/               # Pip package (published to PyPI)
│   ├── admin.py           # Django admin interface
│   ├── admin_auth.py      # Admin authentication logic
│   ├── socialauth/        # Optional django-allauth helpers
│   ├── urls.py            # API routes + override_admin_urls()
│   ├── control/           # Authentication controllers
│   ├── helpers/           # TOTP, passkey, session, backup code helpers
│   ├── docs/              # AUTHENTICATION.md (detailed workflows)
│   └── templates/         # Admin 2FA HTML templates
├── example/               # Local dev/test Django project (not published)
│   ├── devsite/           # Example settings and URLs
│   └── manage.py
├── manage.py              # Forwards to example/manage.py
└── pyproject.toml
```

---

## Quick start

### Basic lokdown setup

1. Add `lokdown` to `INSTALLED_APPS`
2. Include `path("api/", include("lokdown.urls"))`
3. Call `override_admin_urls(urlpatterns)` if using admin 2FA
4. Set `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGINS`
5. Run `python manage.py migrate`

### Login flow (password + optional 2FA)

```bash
# 1. Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'

# 2. If requires_2fa, verify
curl -X POST http://localhost:8000/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"session_id": "<id>", "totp_token": "123456"}'
```

See [Password login and 2FA](#password-login-and-2fa) and [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) for full request/response shapes.

---

## Configuration

### Required settings

```python
# WebAuthn
WEBAUTHN_RP_ID = "localhost"          # Your domain / rpId
WEBAUTHN_RP_NAME = "Your App Name"
WEBAUTHN_ORIGINS = ["http://localhost:8000"]

# Production security
SECURE_SSL_REDIRECT = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
```

### Optional 2FA settings

```python
ADMIN_2FA_REQUIRED = True
BACKUP_CODE_RATE_LIMIT = 10
TWOFA_SESSION_TIMEOUT = 10
BACKUP_CODES_COUNT = 8
BACKUP_CODE_LENGTH = 10
```

### Environment variable reference

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBAUTHN_RP_ID` | `localhost` | Domain for WebAuthn |
| `WEBAUTHN_RP_NAME` | `Your App Name` | Application name |
| `WEBAUTHN_ORIGIN` / `WEBAUTHN_ORIGINS` | — | Allowed WebAuthn origins |
| `BACKUP_CODE_RATE_LIMIT` | `10` | Backup code attempts per minute |
| `TWOFA_SESSION_TIMEOUT` | `10` | 2FA session timeout (minutes) |
| `BACKUP_CODES_COUNT` | `8` | Number of backup codes |
| `BACKUP_CODE_LENGTH` | `10` | Backup code length |
| `ADMIN_2FA_REQUIRED` | `False` | Require 2FA for admin users |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | — | Comma-separated CSRF trusted origins |
| `SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER` | — | Skip `/accounts/login/` HTML (`google`, `github`, …) |

### REST Framework and JWT (example defaults)

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=5),
    "ROTATE_REFRESH_TOKENS": True,
}
```

---

## API reference

Full workflow documentation: **[docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)**

Prefix paths with `/api/` when included as `path("api/", include("lokdown.urls"))`.

| Area | Paths |
|------|--------|
| Login | `auth/login`, `auth/verify`, `auth/token`, `auth/token/verify` |
| OAuth (OpenAPI tag **OAuth**) | `auth/oauth/providers`, `auth/oauth/<provider>/login`, `auth/oauth/callback` |
| TOTP setup | `auth/2fa/setup/totp`, `auth/2fa/verify/totp` |
| Passkey | `auth/2fa/passkey/setup`, `auth/2fa/passkey/verify`, `auth/2fa/passkey/options` |
| Backup / status | `auth/2fa/verify/backup`, `auth/2fa/status`, `auth/2fa/disable` |

Allauth headless (`/_allauth/browser/v1/*`) is not in lokdown OpenAPI; use it for provider discovery and OAuth start, then **OAuth** API helpers for the JWT bridge.

OpenAPI schema in the example project: `example/api_schema.json` — regenerate with `python manage.py spectacular --file api_schema.json`.

---

## Password login and 2FA

### Login initiation

**`POST /api/auth/login`**

```json
{ "username": "your_username", "password": "your_password" }
```

**No 2FA:**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "requires_2fa": false
}
```

**2FA required:**

```json
{
  "session_id": "<uuid>",
  "requires_2fa": true,
  "totp_enabled": true,
  "passkey_enabled": true
}
```

### 2FA verification

**`POST /api/auth/verify`**

```json
{ "session_id": "<uuid>", "totp_token": "123456" }
```

```json
{ "session_id": "<uuid>", "passkey_response": { "id": "...", "response": { ... } } }
```

```json
{ "session_id": "<uuid>", "backup_code": "ABC123DEF4" }
```

### 2FA setup

| Endpoint | Purpose |
|----------|---------|
| `POST /api/auth/2fa/setup/totp` | QR code + secret |
| `POST /api/auth/2fa/verify/totp` | Confirm TOTP; returns backup codes |
| `POST /api/auth/2fa/passkey/setup` | WebAuthn registration options |
| `POST /api/auth/2fa/passkey/verify` | Complete passkey registration |
| `GET /api/auth/2fa/status` | Current 2FA state |
| `POST /api/auth/2fa/disable` | Disable all 2FA methods |

### Passkey frontend example

```javascript
const options = await fetch("/api/auth/2fa/passkey/setup", {
  method: "POST",
  headers: { Authorization: "Bearer " + token },
}).then((r) => r.json());

const credential = await navigator.credentials.create({ publicKey: options });

await fetch("/api/auth/2fa/passkey/verify", {
  method: "POST",
  headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
  body: JSON.stringify({
    session_id: options.session_id,
    passkey_response: credential,
  }),
});
```

### Supported passkey authenticators

- **Hardware:** YubiKey, Feitian, Solo, Titan, any FIDO2 key
- **Platform:** Apple Keychain, Google Password Manager, Windows Hello, Touch ID, Face ID
- **Browsers:** Chrome 67+, Firefox 60+, Safari 13+, Edge 18+

---

## Social login (OAuth)

OAuth is **optional**. Enable only when you need Google/GitHub/etc. sign-in.

### Install and apps

```python
from lokdown.socialauth.settings_helper import (
    LOKDOWN_ALLAUTH_BASE_APPS,
    get_allauth_recommended_settings,
    get_lokdown_socialauth_middleware,
    get_provider_installed_apps,
)
from lokdown.socialauth.urls import get_allauth_urlpatterns

INSTALLED_APPS = [
    "lokdown",
    *LOKDOWN_ALLAUTH_BASE_APPS,
    *get_provider_installed_apps(["google", "github"]),
]

globals().update(get_allauth_recommended_settings())

SITE_ID = 1
LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS = ["google", "github"]
SOCIALACCOUNT_PROVIDERS = {"github": {"VERIFIED_EMAIL": True}}

MIDDLEWARE = [
    # ...
    *get_lokdown_socialauth_middleware(),
]
```

```python
# urls.py
urlpatterns = [
    *get_allauth_urlpatterns(),
    path("api/", include("lokdown.urls")),
]
```

### OAuth credentials (Django admin)

Client IDs and secrets are **not** read from environment variables.

1. Run migrations: `python manage.py migrate`
2. Open **Admin → Social applications**: `/admin/socialaccount/socialapp/`
3. Add a **Social application** per provider
4. Set **Client id** and **Secret key**
5. Under **Sites**, select the site matching `SITE_ID`

Register provider redirect URIs:

| Provider | Redirect URI |
|----------|----------------|
| Google | `https://your-domain/accounts/google/login/callback/` |
| GitHub | `https://your-domain/accounts/github/login/callback/` |

Providers appear in the API only after a linked Social application exists for the current Site.

### SPA-only frontend (recommended)

Your React/Vue/etc. app owns the login UI. With `HEADLESS_ONLY = True` (default via `get_allauth_recommended_settings()`), Django serves the headless API and provider OAuth callbacks only.

**Keep on Django:** `/_allauth/browser/v1/*`, `/accounts/<provider>/login/callback/`, `/api/auth/oauth/callback`

**Skip in your app:** allauth HTML login pages, `/accounts/login/` links

#### Same-origin via Vite proxy (recommended for local dev)

Proxy `/_allauth`, `/accounts`, and `/api` to Django so the OAuth `sessionid` cookie is set on the SPA host. Leave your API base **empty** and use relative URLs. Use **one hostname only** (`http://localhost:5173`, not both `localhost` and `127.0.0.1`).

```javascript
// vite.config.js
export default {
  server: {
    proxy: {
      "/api": "http://localhost:8000",
      "/accounts": "http://localhost:8000",
      "/_allauth": "http://localhost:8000",
    },
  },
};
```

Provider redirect URIs in Google/GitHub consoles use the **Django host**:

`http://localhost:8000/accounts/google/login/callback/`

**Flow:**

1. `GET /_allauth/browser/v1/config` — list providers
2. POST form to `/_allauth/browser/v1/auth/provider/redirect` (synchronous submit, not XHR)
3. After OAuth, allauth redirects to your SPA `callback_url`
4. `POST /api/auth/oauth/callback` with `credentials: "include"` and CSRF — session cookie auth, not Bearer JWT
5. If `requires_2fa`, `POST /api/auth/verify` with `session_id`

```javascript
// Discover providers
const { data } = await fetch("/_allauth/browser/v1/config").then((r) => r.json());
const providers = data.socialaccount.providers;

// Start OAuth — use a form POST (see docs/AUTHENTICATION.md for postForm helper)
// SPA callback route (/oauth/callback)
const csrfToken = document.cookie.match(/csrftoken=([^;]+)/)?.[1] ?? "";
const payload = await fetch("/api/auth/oauth/callback", {
  method: "POST",
  credentials: "include",
  headers: { "X-CSRFToken": csrfToken },
}).then((r) => r.json());
```

Restart Vite after changing `vite.config.js` proxy rules.

#### Cross-origin SPA (separate API host)

When the SPA and API run on different origins (e.g. `:5173` and `:8000`):

```python
SOCIALACCOUNT_LOGIN_ON_GET = True
CSRF_TRUSTED_ORIGINS = ["http://localhost:5173", "http://localhost:8000"]
CORS_ALLOWED_ORIGINS = ["http://localhost:5173"]
CORS_ALLOW_CREDENTIALS = True
```

Use absolute `next` URLs and `credentials: "include"`. POST requests need `X-CSRFToken`.

See [docs/AUTHENTICATION.md — SPA-only frontend](docs/AUTHENTICATION.md#spa-only-frontend-no-django-html-templates) and [OAuth workflow](docs/AUTHENTICATION.md#api-workflow-login-with-external-provider-oauth).

### OAuth API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/auth/oauth/providers` | None | List providers + headless redirect metadata |
| GET | `/api/auth/oauth/{provider}/login` | None | Single provider headless redirect metadata |
| POST | `/api/auth/oauth/callback` | Django session + CSRF | Session → JWT or `session_id` |

---

## Local development (example project)

The `example/` directory is **not** published to PyPI. It runs django-lokdown from the repository for manual testing, including Google and GitHub OAuth.

### Setup

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cd example
python manage.py migrate
python manage.py runserver
```

Or: `./scripts/runserver.sh`

Default admin credentials after migrate: `admin` / `password`

### Dev URLs

| URL | Purpose |
|-----|---------|
| http://localhost:8000/ | Minimal dev home (Swagger link) |
| http://localhost:8000/api/schema/swagger-ui/ | OpenAPI / Swagger UI |
| http://localhost:8000/admin/ | Django admin |
| http://localhost:8000/auth/callback | Optional HTML/JSON OAuth bridge (dev only) |
| http://localhost:8000/oauth/callback | Alias of `/auth/callback` |

Use **one hostname** consistently (`localhost` or `127.0.0.1`) for OAuth, admin, and your SPA.

### Example project files

| File | Role |
|------|------|
| `example/devsite/settings.py` | allauth apps, middleware, CORS, CSRF |
| `example/devsite/socialauth_settings.py` | Supported providers and provider options |
| `example/devsite/auth_views.py` | Optional HTML/JSON `/auth/callback` (dev) |
| `example/devsite/urls.py` | `get_allauth_urlpatterns()` + `include(lokdown.urls)` |
| `example/api_schema.json` | Committed OpenAPI snapshot |

Regenerate schema:

```bash
cd example
python manage.py spectacular --file api_schema.json
```

### Contributing to the library

```bash
git clone https://github.com/your-username/django-lokdown.git
cd django-lokdown
pip install -e ".[dev]"
python manage.py migrate
python manage.py runserver
```

---

## Django admin

### Admin models

- **UserTimeBasedOneTimePasswords**: TOTP settings
- **PasskeyCredential**: WebAuthn credentials
- **BackupCodes**: Backup code management
- **LoginSession**: Active login sessions
- **FailedBackupCodeAttempt**: Failed backup code tracking

Access at `/admin/`

### Admin 2FA (`ADMIN_2FA_REQUIRED = True`)

```python
from lokdown.urls import override_admin_urls

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("lokdown.urls")),
]
urlpatterns = override_admin_urls(urlpatterns)
```

**First-time setup:** login → choose TOTP or Passkey → verify → backup codes → admin dashboard

**Subsequent login:** login → TOTP / passkey / backup code → admin dashboard

**Features:**

- One-click 2FA method selection (no confirmation buttons)
- Verification-before-save for TOTP
- Automatic passkey prompts
- Backup code display and download (TXT/CSV)
- Dark mode support
- Security dashboard with adoption statistics

**Note:** If a user is already signed in via OAuth and then completes admin 2FA, lokdown clears the pending session key before switching users to avoid session flush errors.

---

## Models

### UserTimeBasedOneTimePasswords

- `user`, `totp_secret`, `pending_totp_secret`, `created_at`, `updated_at`, `last_used`

### PasskeyCredential

- `user`, `credential_id`, `public_key`, `sign_count`, `transports`, `rp_id`, `user_handle`, `created_at`, `last_used`

### BackupCodes

- `user`, `codes`, `created_at`, `updated_at`

### LoginSession

- `user`, `session_id`, `is_authenticated`, `requires_2fa`, `totp_verified`, `passkey_verified`, `challenge`, `expires_at`, `ip_address`, `user_agent`

### FailedBackupCodeAttempt

- `user`, `ip_address`, `user_agent`, `attempted_code`, `created_at`

---

## Management commands

```bash
# Security audit (report only)
python manage.py security_audit --days 30 --export

# Preview cleanup (dry-run)
python manage.py security_audit --cleanup

# Apply cleanup
python manage.py security_audit --cleanup --force
```

---

## Customization

### Custom user model

```python
AUTH_USER_MODEL = "your_app.YourUserModel"
```

### Custom admin 2FA templates

Override in your project `templates/`:

- `2fa_setup.html`, `2fa_verify.html`, `2fa_setup_totp.html`, `2fa_setup_passkey.html`
- `templates/admin/security_dashboard.html`

---

## Security

1. **Rate limiting** — backup codes: 10 attempts/minute/IP; failed attempts logged
2. **Session management** — login sessions expire (default 10 minutes)
3. **Backup codes** — single-use, removed after verification
4. **Verification-before-save** — TOTP saved only after successful verification
5. **HTTPS** — required for WebAuthn in production
6. **JWT** — use `Authorization: Bearer` for API calls after login

### Session and backup code behavior

- Login sessions tied to IP and user agent
- 8 backup codes generated on TOTP/passkey setup (configurable)
- Passkey sign count prevents replay attacks

---

## System checks

Lokdown registers warnings when `DEBUG` is False (and for social auth when configured):

| ID | Topic |
|----|--------|
| `lokdown.W001` | `ADMIN_2FA_REQUIRED` not set |
| `lokdown.W002` | `WEBAUTHN_ORIGINS` not configured |
| `lokdown.W003` | `SITE_ID` missing (social auth) |
| `lokdown.W004` | `SOCIALACCOUNT_ADAPTER` not set to lokdown adapter |

```bash
python manage.py check
```

---

## Dependencies

- `django-ratelimit` — rate limiting
- `django-allauth[socialaccount]` — bundled; enable in `INSTALLED_APPS` only for OAuth
- `pyotp` — TOTP
- `webauthn` — passkeys
- `qrcode`, `Pillow` — QR codes
- `djangorestframework`, `djangorestframework-simplejwt`, `drf-spectacular`, `django-cors-headers`

---

## License, contributing, and support

Install from PyPI as `django-lokdown` or from source with `pip install -e .`.

This project is licensed under the **GNU General Public License v3.0**. See the LICENSE file.

Contributions are welcome via Pull Request.

**Support:** loknuslabs@gmail.com — https://loknuslabs.io
