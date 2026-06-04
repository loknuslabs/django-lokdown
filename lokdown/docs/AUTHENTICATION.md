# Lokdown authentication workflow

This document describes how lokdown handles password login, two-factor authentication (2FA), JWT issuance, 2FA enrollment, and Django admin integration after the control-layer refactor.

All business logic lives in `lokdown/helpers/auth_flow_helper.py`. HTTP handlers are thin controllers under `lokdown/control/`. Request and response shapes are defined in `lokdown/serializers/`.

---

## Concepts

### What counts as “2FA enabled”

A user has 2FA enabled when **either** TOTP or at least one passkey is configured:

- TOTP: `UserTimeBasedOneTimePasswords.totp_secret` is set
- Passkey: one or more `PasskeyCredential` rows exist

Backup codes alone do **not** enable 2FA. They are a recovery factor used only after a primary method exists.

### LoginSession

Pending logins (password OK, 2FA not yet done) use a `LoginSession` row:

| Field | Purpose |
|--------|---------|
| `session_id` | Opaque UUID returned to the client |
| `expires_at` | Short-lived (default `TWOFA_SESSION_TIMEOUT` minutes) |
| `requires_2fa` | Always true for these sessions |
| `challenge` | WebAuthn challenge (passkey login or passkey setup) |
| `is_authenticated` | Set true after JWT is issued; blocks reuse |
| `totp_verified` / `passkey_verified` | Set when that factor succeeds (backup does not set these) |

Sessions are single-use for token completion: once `is_authenticated` is true, verification endpoints reject the session.

### Two login stacks (same logic, different response keys)

| Stack | Step 1 | Step 2 | Token JSON keys |
|--------|--------|--------|-----------------|
| **REST login** | `POST /api/auth/login` | `POST /api/auth/verify` | `access_token`, `refresh_token` |
| **SimpleJWT** | `POST /api/auth/token` | `POST /api/auth/token/verify` | `access`, `refresh` |

Both call `initiate_password_login()` and `verify_second_factor()` in `auth_flow_helper.py`.

### External provider login (OAuth)

| Stack | Step 1 | Step 2 | Step 3 | Step 4 (if 2FA) | Token JSON keys |
|--------|--------|--------|--------|-----------------|-----------------|
| **OAuth + REST** | `GET /api/auth/oauth/<provider>/login` → open `login_url` | Browser OAuth (`/accounts/…`) | `GET /api/auth/oauth/callback` (session cookie) | `POST /api/auth/verify` | `access_token`, `refresh_token` |
| **OAuth + SimpleJWT** | Same | Same | Same | `POST /api/auth/token/verify` | `access`, `refresh` |

Step 1–3 are documented in OpenAPI under the **OAuth** tag (`example/api_schema.json`). `/accounts/*` allauth routes are browser-only and do not appear in the schema.

OAuth completes with a **Django session** (`request.user`). Lokdown JWTs are issued at step 3 via `bridge_oauth_session_to_lokdown` / `initiate_password_login`. See [Login with external provider](#api-workflow-login-with-external-provider-oauth).

### Passkey login requires a challenge step

Passkey verification checks `LoginSession.challenge`. Before calling verify:

1. Complete password login → receive `session_id`
2. `POST /api/auth/2fa/passkey/options` with `session_id` → server stores challenge
3. Run WebAuthn `navigator.credentials.get()` in the browser
4. Submit `passkey_response` to verify

---

## Project setup

### `settings.py`

```python
INSTALLED_APPS = [
    # ...
    "lokdown",
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",  # optional, for OpenAPI
]

# WebAuthn (required for passkeys)
WEBAUTHN_RP_ID = "localhost"          # fallback rpId; admin/API use request hostname when available
WEBAUTHN_RP_NAME = "My Application"
WEBAUTHN_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
WEBAUTHN_ORIGIN = "http://localhost:8000"  # optional; first origin if ORIGINS unset

# 2FA behaviour
TWOFA_SESSION_TIMEOUT = 10            # minutes, pending LoginSession lifetime
BACKUP_CODE_RATE_LIMIT = 10           # attempts per IP per minute
BACKUP_CODES_COUNT = 8
BACKUP_CODE_LENGTH = 10
ADMIN_2FA_REQUIRED = True             # custom admin login + 2FA routes
```

### Root `urls.py`

```python
from django.urls import path, include
from lokdown.urls import override_admin_urls

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("lokdown.urls")),
]

urlpatterns = override_admin_urls(urlpatterns)
```

`override_admin_urls()` replaces the project `admin/` include with lokdown admin routes (2FA login when `ADMIN_2FA_REQUIRED`, plus staff self-service setup URLs).

### Migrations

```bash
python manage.py migrate lokdown
```

If you enable social login (allauth in `INSTALLED_APPS`):

```bash
python manage.py migrate sites
```

---

## Social login (django-allauth)

Lokdown ships helpers around **django-allauth** so SPAs can use OAuth providers (Google, GitHub, Microsoft, etc.) alongside lokdown’s password + 2FA JWT APIs.

### Optional integration

Social login is **optional**. You only need the steps below if you want OAuth in your project.

| Scenario | What to do |
|----------|------------|
| Password + 2FA JWT only | Add `lokdown` only. Do **not** add allauth apps or `SOCIALACCOUNT_PROVIDERS`. |
| OAuth + lokdown | Follow **Install and apps** below. |

**Without allauth in `INSTALLED_APPS`:**

- `python manage.py check` runs normally (no allauth import during lokdown checks).
- Lokdown JWT and 2FA APIs work unchanged.
- The `example/` dev project ships this way by default.

**With allauth configured:** mount URLs, middleware, and provider credentials as below.

Social login establishes a **Django session** via allauth. Your frontend callback route (for example `/auth/callback`) is responsible for exchanging that session for lokdown JWTs if needed.

### Install and apps

`django-allauth[socialaccount]` is installed with `django-lokdown`. You must also add allauth to **`INSTALLED_APPS`** in your project:

```python
from lokdown.socialauth.settings_helper import (
    LOKDOWN_ALLAUTH_BASE_APPS,
    get_allauth_recommended_settings,
    get_lokdown_socialauth_middleware,
    get_provider_installed_apps,
)

INSTALLED_APPS = [
    # ...
    "lokdown",
    *LOKDOWN_ALLAUTH_BASE_APPS,
    *get_provider_installed_apps(["google", "github"]),  # only providers you enable
]

# Merge recommended defaults (adapter, backends, SITE_ID, email settings)
globals().update(get_allauth_recommended_settings())

SITE_ID = 1

SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "APPS": [
            {
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "secret": os.environ["GOOGLE_CLIENT_SECRET"],
            },
        ],
    },
    "github": {
        "APPS": [
            {
                "client_id": os.environ["GITHUB_CLIENT_ID"],
                "secret": os.environ["GITHUB_CLIENT_SECRET"],
            },
        ],
    },
}

MIDDLEWARE = [
    # ...
    *get_lokdown_socialauth_middleware(),
]
```

`get_lokdown_socialauth_middleware()` returns, in order:

1. `allauth.account.middleware.AccountMiddleware` (required by django-allauth)
2. `RedirectAuthenticatedSocialLoginMiddleware`
3. `AutoRedirectAccountLoginToSocialMiddleware`

### CustomSocialAccountAdapter

Set in recommended settings as `SOCIALACCOUNT_ADAPTER = "lokdown.socialauth.adapters.CustomSocialAccountAdapter"`.

On social signup, `populate_user()` sets `username` from the provider email (truncated to 150 characters). If that username exists, it appends `_1`, `_2`, etc. Import from:

```python
from lokdown.socialauth.adapters import CustomSocialAccountAdapter
# or: from lokdown.socialauth import CustomSocialAccountAdapter  # lazy import
```

Middleware and adapter classes use **lazy imports** in `lokdown.socialauth` so projects without allauth in `INSTALLED_APPS` do not load allauth at startup. Settings helpers (`lokdown.socialauth.settings_helper`) are safe to import anytime.

### URLs

```python
from django.urls import path, include
from lokdown.socialauth.urls import get_allauth_urlpatterns
from lokdown.urls import override_admin_urls

urlpatterns = [
    *get_allauth_urlpatterns(),  # mounts allauth at /accounts/
    path("api/", include("lokdown.urls")),
    path("auth/callback", your_jwt_callback_view, name="auth_callback"),
]

urlpatterns = override_admin_urls(urlpatterns)
```

Provider login URLs follow allauth conventions, for example:

| Provider | Login URL | URL name |
|----------|-----------|----------|
| Google | `/accounts/google/login/` | `google_login` |
| GitHub | `/accounts/github/login/` | `github_login` |

### Lokdown middleware

| Middleware | Purpose |
|------------|---------|
| `RedirectAuthenticatedSocialLoginMiddleware` | If the user is already signed in, skip OAuth when hitting `/accounts/<provider>/login/?next=...` (SPA retries). Honors `process=connect` for account linking. |
| `AutoRedirectAccountLoginToSocialMiddleware` | When enabled, `GET /accounts/login/` redirects to a provider instead of the email form. |

Settings:

| Setting | Description |
|---------|-------------|
| `SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER` | Provider id for auto-redirect (e.g. `"google"`). |
| `SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_GOOGLE` | Legacy bool; equivalent to provider `"google"`. |
| `LOKDOWN_SOCIALAUTH_CALLBACK_URL_NAME` | URL name when `?next=` is absent (default `auth_callback`). |
| `LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS` | Optional explicit list for middleware path matching. |
| `LOKDOWN_SOCIALAUTH_ACCOUNT_URL_PREFIX` | URL prefix if not `accounts` (default `accounts`). |

Opt out of auto-redirect to see the local login form: `GET /accounts/login/?local=1` (also `?password=` or `?email=`).

### System checks

Lokdown registers two social-auth checks (`lokdown.W003`, `lokdown.W004`). They run **only when both** are true:

1. `"allauth"` is in `INSTALLED_APPS`
2. At least one provider is configured (`SOCIALACCOUNT_PROVIDERS` with `APPS`/`APP`, or non-empty `LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS`)

| Check ID | Condition warned |
|----------|------------------|
| `lokdown.W003` | `SITE_ID` is not set |
| `lokdown.W004` | `SOCIALACCOUNT_ADAPTER` is not `lokdown.socialauth.adapters.CustomSocialAccountAdapter` |

If you have `SOCIALACCOUNT_PROVIDERS` in settings but forgot to add allauth apps, checks are **skipped** (no crash on `manage.py check`).

Verify after setup:

```bash
python manage.py check
python manage.py migrate sites
```

### OpenAPI / Swagger (`api_schema.json`)

Lokdown registers **DRF** OAuth helpers in [drf-spectacular](https://drf-spectacular.readthedocs.io/). They appear in Swagger UI and in a checked-in schema file in the example project.

| What appears in OpenAPI | What does not |
|-------------------------|---------------|
| `GET /api/auth/oauth/providers` | `GET /accounts/google/login/` (allauth HTML/redirect) |
| `GET /api/auth/oauth/{provider}/login` | `GET /accounts/login/` |
| `GET /api/auth/oauth/callback` | Other `/accounts/*` routes |

**Regenerate** (from your Django project root, with `drf_spectacular` installed):

```bash
python manage.py spectacular --file api_schema.json
```

Example project:

```bash
cd example
python manage.py spectacular --file api_schema.json
# View: http://127.0.0.1:8000/api/schema/swagger-ui/
```

**OpenAPI components** (in `components.schemas`):

| Schema | Used by |
|--------|---------|
| `OAuthProvidersResponse` | `GET auth/oauth/providers` |
| `OAuthLoginUrlResponse` | `GET auth/oauth/{provider}/login` |
| `OAuthSessionBridgeResponse` | `GET auth/oauth/callback` |

Implementation: `lokdown/control/socialauth_controller.py`, serializers in `lokdown/serializers/socialauth.py`.

---

## API workflow: login with external provider (OAuth)

This section describes the **end-to-end path** from Google/GitHub/etc. to lokdown JWTs, including 2FA.

### Two layers of authentication

| Layer | Established by | Used for |
|-------|----------------|----------|
| **Django session** | django-allauth after OAuth | Browser cookie; `request.user` in views |
| **Lokdown JWT** | `initiate_password_login` + optional `verify_second_factor` | `Authorization: Bearer` on `/api/*` |

Lokdown does not expose a dedicated “OAuth token” endpoint. After OAuth, your **`auth_callback`** view (or an API called with session cookies) must call the same helpers as password login.

### Overview

```mermaid
sequenceDiagram
    participant SPA as SPA / browser
    participant OAuth as Provider (Google, etc.)
    participant Allauth as Django + allauth
    participant CB as auth_callback (your view)
    participant API as lokdown /api/auth/*

    SPA->>Allauth: GET /accounts/google/login/?next=/auth/callback
    alt User already has Django session
        Allauth-->>SPA: 302 /auth/callback
    else OAuth required
        Allauth->>OAuth: Authorize
        OAuth-->>Allauth: Callback + code
        Allauth-->>SPA: 302 /auth/callback (session cookie)
    end
    SPA->>CB: GET /auth/callback (with session cookie)
    CB->>CB: initiate_password_login(user, request)
    alt 2FA not enabled
        CB-->>SPA: JWT access + refresh
    else 2FA enabled
        CB-->>SPA: session_id + requires_2fa flags
        SPA->>API: POST /api/auth/verify (TOTP / passkey / backup)
        API-->>SPA: JWT access + refresh
    end
```

### Step 1 — Start OAuth (browser)

**Option A — from OpenAPI-documented API** (recommended for SPAs):

```http
GET /api/auth/oauth/google/login?next=/auth/callback
```

**200 response**

```json
{
  "provider": "google",
  "login_url": "http://127.0.0.1:8000/accounts/google/login/?next=%2Fauth%2Fcallback",
  "next": "/auth/callback"
}
```

Redirect the browser to `login_url`. List all providers with `GET /api/auth/oauth/providers`.

**Option B — direct allauth URL**

```text
GET /accounts/google/login/?next=/auth/callback
GET /accounts/github/login/?next=/auth/callback
```

| Query param | Purpose |
|-------------|---------|
| `next` | Post-login redirect (your SPA callback route) |
| `process=connect` | Link provider to an **already signed-in** user (skip lokdown middleware short-circuit) |

**Middleware behavior:**

- If the user already has a Django session and opens `/accounts/google/login/?next=...` (without `process=connect`), lokdown redirects straight to `next` (or `auth_callback`) instead of re-running OAuth.
- Use that for SPA retries; use `process=connect` only when linking another social account in account settings.

### Step 2 — OAuth completes (allauth)

Allauth:

1. Creates or loads a `User` (new signups get `username` from email via `CustomSocialAccountAdapter`).
2. Links a `SocialAccount` row to the provider.
3. Calls Django `login()` and sets the **session cookie**.
4. Redirects to `next` (e.g. `/auth/callback`).

No lokdown `LoginSession` or JWT exists yet.

### Step 3 — Bridge session to lokdown

Call **`GET /api/auth/oauth/callback`** with the **session cookie** from OAuth (documented in Swagger under tag **OAuth**).

Or implement a browser view at `auth_callback` that calls the same logic (`bridge_oauth_session_to_lokdown` / `initiate_password_login`). It does **not** re-check a password; it only tests whether lokdown 2FA is enabled:

```http
GET /api/auth/oauth/callback
Cookie: sessionid=...
```

**Example `auth_callback` view** (HTML for local dev):

```python
from django.http import JsonResponse
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required

from lokdown.helpers.auth_flow_helper import initiate_password_login


@login_required
def auth_callback(request):
    try:
        payload = initiate_password_login(request.user, request)
    except RuntimeError:
        return JsonResponse({"error": "Failed to create authentication session"}, status=500)

    if payload.get("requires_2fa"):
        # Option A: SPA — redirect with session_id in query (hash or search)
        return redirect(f"/app/2fa?session_id={payload['session_id']}")
        # Option B: JSON API — return payload for XHR/fetch (ensure CORS + credentials)
        # return JsonResponse(payload)

    # No 2FA — return or store JWTs
    return redirect(
        f"/app/home#access_token={payload['access_token']}&refresh_token={payload['refresh_token']}"
    )
    # Prefer HttpOnly cookies or a secure backend-for-frontend over URL fragments in production.
```

**200-equivalent payloads** (same shape as `POST /api/auth/login`):

**No 2FA**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "requires_2fa": false
}
```

**2FA required**

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "requires_2fa": true,
  "totp_enabled": true,
  "passkey_enabled": true,
  "backup_codes_available": true
}
```

### Step 4 — Complete 2FA (if required)

Identical to [login with 2FA](#api-workflow-login-with-2fa). The `session_id` from step 3 is a lokdown `LoginSession`, not the Django session id.

```http
POST /api/auth/verify
Content-Type: application/json

{
  "session_id": "<from callback>",
  "totp_token": "123456"
}
```

Passkey flow still requires `POST /api/auth/2fa/passkey/options` before verify. Use `POST /api/auth/token/verify` if your app uses the SimpleJWT key names (`access` / `refresh`).

### Decision matrix

| User state | After OAuth | Callback (`initiate_password_login`) | Client next step |
|------------|-------------|-----------------------------------|------------------|
| New user, no 2FA | Django session | JWT immediately | Store tokens; call `/api/*` |
| New user, 2FA enabled* | Django session | `session_id` + flags | Run 2FA verify flow |
| Returning user, no 2FA | Django session | JWT immediately | Store tokens |
| Returning user, 2FA on | Django session | `session_id` + flags | Run 2FA verify flow |
| Already logged in (SPA retry) | Session exists | Middleware → `next` without OAuth | Run callback bridge again |

\*2FA is only required if TOTP or passkeys were already enrolled; new OAuth users typically have neither until they enroll via authenticated `/api/auth/2fa/*` routes.

### New signup vs returning login

| Event | What happens |
|-------|----------------|
| **First OAuth login** | allauth creates `User`; adapter sets `username` from email; `SocialAccount` created |
| **Repeat OAuth login** | allauth matches existing `SocialAccount` / email; same `User` gets Django session |
| **Email already exists (local account)** | Controlled by allauth settings (`SOCIALACCOUNT_EMAIL_AUTHENTICATION`, etc. in `get_allauth_recommended_settings()`) — may auto-connect or require account pairing per your allauth config |

### Account linking (`process=connect`)

For logged-in users adding another provider:

```text
GET /accounts/github/login/?process=connect&next=/settings/accounts
```

Do **not** run the JWT bridge on `connect` completion unless the product flow requires it; the user is already authenticated. Lokdown middleware intentionally does not short-circuit these requests.

### SPA implementation patterns

| Pattern | OAuth start | Callback | 2FA |
|---------|-------------|----------|-----|
| **Full redirect** | `window.location = '/accounts/google/login/?next=/auth/callback'` | Server view returns redirect to `/app/2fa?...` or home | Same-origin or API calls with stored `session_id` |
| **Popup + callback page** | Popup opens provider URL; callback page `postMessage` to opener | Callback page reads session via server render | Opener calls `/api/auth/verify` |
| **BFF (recommended)** | Same | Callback sets HttpOnly cookies server-side | BFF proxies verify |

Requirements:

- Callback and OAuth URLs must be **same-site** (or configured CSRF/trusted origins) so the session cookie is sent.
- For `fetch` to `/api/auth/verify` after OAuth, use `credentials: 'include'` only if your API shares session cookies; otherwise pass `session_id` in JSON from the callback response (common for SPAs on another origin).

### What not to do

- Do not call `POST /api/auth/login` with an empty or dummy password after OAuth — password auth is separate.
- Do not treat the Django session id as lokdown’s `session_id`; they are different systems.
- Do not skip the callback bridge if the SPA needs JWTs — allauth alone does not return lokdown tokens.

### Provider entry points (quick reference)

| Provider | Start login | URL name |
|----------|-------------|----------|
| Google | `/accounts/google/login/?next=/auth/callback` | `google_login` |
| GitHub | `/accounts/github/login/?next=/auth/callback` | `github_login` |
| Microsoft | `/accounts/microsoft/login/?next=/auth/callback` | `microsoft_login` |

Auto-redirect from account login (optional): set `SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER = "google"` so `GET /accounts/login/` goes straight to Google unless `?local=1`.

---

## Architecture

```mermaid
flowchart TB
    subgraph clients [Clients]
        SPA[SPA / mobile app]
        Admin[Django admin browser]
    end

    subgraph api [API layer - lokdown/control]
        AC[auth_controller]
        TC[token_controller]
        TOTP[totp_controller]
        PK[passkey_controller]
        BC[backup_code_controller]
        TF[twofa_controller]
    end

    subgraph core [Business logic]
        AF[auth_flow_helper.py]
    end

    subgraph data [Data]
        LS[(LoginSession)]
        TOTP_M[(UserTimeBasedOneTimePasswords)]
        PK_M[(PasskeyCredential)]
        BK[(BackupCodes)]
    end

    SPA --> AC & TC & TOTP & PK & BC & TF
    Admin --> AdminAuth[admin_auth.py]
    AdminAuth --> AF
    AC & TC & TOTP & PK & BC & TF --> AF
    AF --> LS & TOTP_M & PK_M & BK
```

---

## API workflow: login without 2FA

User has no TOTP secret and no passkeys.

```http
POST /api/auth/login
Content-Type: application/json

{"username": "jane", "password": "secret"}
```

**200 response**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "requires_2fa": false
}
```

Use `Authorization: Bearer <access_token>` on protected routes.

**SimpleJWT equivalent:** `POST /api/auth/token` with the same body returns `access` / `refresh` immediately when 2FA is off.

---

## API workflow: login with 2FA

### Step 1 — Password

```http
POST /api/auth/login
Content-Type: application/json

{"username": "jane", "password": "secret"}
```

**200 response** (2FA required)

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "requires_2fa": true,
  "totp_enabled": true,
  "passkey_enabled": true,
  "backup_codes_available": true
}
```

Use the flags to show only supported second-factor options in the UI.

**SimpleJWT:** `POST /api/auth/token` returns **401** with the same pre-2FA body when 2FA is required (not an error in the usual sense—check `requires_2fa` in the JSON).

### Step 2a — Complete with TOTP

```http
POST /api/auth/verify
Content-Type: application/json

{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "totp_token": "123456"
}
```

**200 response**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "requires_2fa": false
}
```

### Step 2b — Complete with passkey

**2b.1 — Fetch authentication options**

```http
POST /api/auth/2fa/passkey/options
Content-Type: application/json

{"session_id": "550e8400-e29b-41d4-a716-446655440000"}
```

**200 response** (abbreviated)

```json
{
  "challenge": "<base64>",
  "rp_id": "localhost",
  "timeout": 60000,
  "options": { }
}
```

**2b.2 — Browser WebAuthn** — call `navigator.credentials.get()` using `options` (or challenge/rpId).

**2b.3 — Verify**

```http
POST /api/auth/verify
Content-Type: application/json

{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "passkey_response": { }
}
```

`passkey_response` is the JSON-serialized `PublicKeyCredential` from the browser.

### Step 2c — Complete with backup code

Either include `backup_code` on `POST /api/auth/verify`, or use the dedicated endpoint:

```http
POST /api/auth/2fa/verify/backup
Content-Type: application/json

{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "backup_code": "ABCD1234EF"
}
```

**200 response**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "requires_2fa": false,
  "message": "Backup code verified successfully"
}
```

Backup codes are **single-use**. Failed attempts are logged (`FailedBackupCodeAttempt`) and rate-limited per IP (`BACKUP_CODE_RATE_LIMIT` per minute).

**JWT completion:** Same bodies for step 2, but use `POST /api/auth/token/verify` and expect `access` / `refresh` in the response.

---

## API workflow: enroll 2FA (authenticated user)

All setup endpoints require `Authorization: Bearer <access_token>`. Enrollment applies to **the authenticated user** (no `user_id` in the body).

### Enroll TOTP

**1. Start setup**

```http
POST /api/auth/2fa/setup/totp
Authorization: Bearer <access_token>
```

**200 response**

```json
{
  "secret": "BASE32SECRET",
  "qr_code": "<base64 png>",
  "provisioning_uri": "otpauth://totp/..."
}
```

Show the QR code or provisioning URI. The secret is stored **server-side** as a pending value until verification succeeds.

**2. Confirm**

```http
POST /api/auth/2fa/verify/totp
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "totp_token": "123456"
}
```

**200 response**

```json
{
  "message": "TOTP setup verified successfully",
  "backup_codes": ["ABCD1234EF", "GHI5678JKL0"]
}
```

On success, lokdown saves the secret and generates a **new** set of backup codes. Save them immediately; they are not returned again via the API.

### Enroll passkey

**1. Start registration**

```http
POST /api/auth/2fa/passkey/setup
Authorization: Bearer <access_token>
```

**200 response**

```json
{
  "session_id": "<uuid>",
  "options": { }
}
```

**2. Browser WebAuthn** — `navigator.credentials.create()` with `options`.

**3. Complete registration**

```http
POST /api/auth/2fa/passkey/verify
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "session_id": "<uuid from step 1>",
  "passkey_response": { }
}
```

**200 response**

```json
{
  "message": "Passkey setup verified successfully",
  "backup_codes": ["ABCD1234EF", "GHI5678JKL0"]
}
```

The credential is saved after verification. A fresh set of backup codes is generated and returned in the response (same as TOTP setup). Store them immediately; they are not returned again via the API.

### Manage passkeys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/auth/2fa/passkey/credentials` | Yes | List credentials |
| DELETE | `/api/auth/2fa/passkey/remove?credential_id=...` | Yes | Remove one credential |

---

## API workflow: 2FA status and disable

### Status

```http
GET /api/auth/2fa/status
Authorization: Bearer <access_token>
```

**200 response**

```json
{
  "is_enabled": true,
  "totp_enabled": true,
  "passkey_enabled": false
}
```

### Disable all 2FA

```http
POST /api/auth/2fa/disable
Authorization: Bearer <access_token>
```

Clears TOTP secret, deletes all passkeys, and empties backup codes.

---

## Django admin workflow

When `ADMIN_2FA_REQUIRED = True`, staff use lokdown’s admin routes under `/admin/` (via `override_admin_urls`).

### First login (no 2FA configured yet)

```mermaid
sequenceDiagram
    participant U as Staff user
    participant A as /admin/login/
    participant S as /admin/2fa/setup/
    participant B as Backup codes page

    U->>A: username + password
    A->>S: LoginSession in Django session
    U->>S: Choose TOTP or passkey
    alt TOTP
        S->>S: QR + pending_totp_secret
        U->>S: Verify code
    else Passkey
        S->>S: WebAuthn register
    end
    S->>B: Show backup codes
    U->>B: Acknowledge
    B->>U: Redirect to admin index
```

| Step | URL | Notes |
|------|-----|--------|
| Login | `/admin/login/` | Password only; creates `LoginSession`, stores `admin_2fa_session_id` in Django session |
| Setup hub | `/admin/2fa/setup/` | Choose TOTP or passkey |
| TOTP setup | `/admin/2fa/verify/totp/` | Secret in session until verified |
| Passkey setup | `/admin/2fa/setup/passkey/` | Uses same helpers as API |
| Backup codes | `/admin/2fa/backup-codes/` | Shown after first enrollment |

### Subsequent logins (2FA already enabled)

| Step | URL | Notes |
|------|-----|--------|
| Login | `/admin/login/` | Password → redirect to verify |
| Verify | `/admin/2fa/verify/` | TOTP, passkey, or backup code |
| Passkey challenge | `POST /api/auth/admin/2fa/passkey/options` | Called from verify template (Django session cookie); stores challenge on `LoginSession` |

On success, lokdown calls Django `login()` with the **model backend** explicitly (required when `AUTHENTICATION_BACKENDS` includes allauth) and clears `admin_2fa_session_id`.

### Staff self-service (already logged into admin)

Available even when `ADMIN_2FA_REQUIRED` is false:

| URL | Purpose |
|-----|---------|
| `/admin/current-user/totp-setup/` | Add/replace TOTP |
| `/admin/current-user/passkey-setup/` | Add passkey |
| `/admin/current-user/backup-codes/` | View codes after setup |

---

## Endpoint reference

Base path assumes `path("api/", include("lokdown.urls"))`.

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `auth/login` | No | Password login → tokens or pre-2FA session |
| POST | `auth/verify` | No | Complete 2FA → `access_token` / `refresh_token` |
| POST | `auth/token` | No | SimpleJWT obtain (same semantics as login) |
| POST | `auth/token/refresh` | No | Refresh JWT |
| POST | `auth/token/verify` | No | Complete 2FA → `access` / `refresh` |

### 2FA enrollment & management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `auth/2fa/setup/totp` | Yes | Generate secret + QR |
| POST | `auth/2fa/verify/totp` | Yes | Confirm TOTP + create backup codes |
| POST | `auth/2fa/passkey/setup` | Yes | WebAuthn registration options |
| POST | `auth/2fa/passkey/verify` | Yes | Complete passkey registration |
| POST | `auth/2fa/passkey/options` | No | Passkey auth options (login session) |
| GET | `auth/2fa/passkey/credentials` | Yes | List passkeys |
| DELETE | `auth/2fa/passkey/remove` | Yes | Remove passkey (`?credential_id=`) |
| POST | `auth/2fa/verify/backup` | No | Login with backup code + tokens |
| GET | `auth/2fa/status` | Yes | 2FA status |
| POST | `auth/2fa/disable` | Yes | Remove all 2FA |

### External provider (OAuth)

**Browser (django-allauth)** — mounted at `/accounts/` via `get_allauth_urlpatterns()`, not auto-listed in OpenAPI:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `accounts/<provider>/login/` | No | Start OAuth in browser (`?next=/auth/callback`) |
| GET | `auth/callback` (your view) | Django session | HTML/JSON bridge after OAuth |

**DRF helpers (documented in OpenAPI / Swagger)** — use these from SPAs and `api_schema.json`:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `auth/oauth/providers` | No | List configured providers + absolute `login_url` (`?next=` optional) |
| GET | `auth/oauth/<provider>/login` | No | Single provider `login_url` for browser redirect |
| GET | `auth/oauth/callback` | Yes (session) | Session → JWT or pre-2FA `session_id` (same as password login) |

After `GET auth/oauth/callback` returns `requires_2fa: true`, use `POST auth/verify` as usual. See [OAuth workflow](#api-workflow-login-with-external-provider-oauth).

#### `GET /api/auth/oauth/providers`

List providers configured in `SOCIALACCOUNT_PROVIDERS` / `LOKDOWN_SOCIALAUTH_ENABLED_PROVIDERS`.

```http
GET /api/auth/oauth/providers?next=/auth/callback
```

**200**

```json
{
  "providers": [
    {
      "id": "google",
      "login_url": "http://127.0.0.1:8000/accounts/google/login/?next=%2Fauth%2Fcallback"
    },
    {
      "id": "github",
      "login_url": "http://127.0.0.1:8000/accounts/github/login/?next=%2Fauth%2Fcallback"
    }
  ]
}
```

**503** — allauth not in `INSTALLED_APPS` or no provider credentials configured.

#### `GET /api/auth/oauth/{provider}/login`

```http
GET /api/auth/oauth/google/login?next=/auth/callback
```

**200**

```json
{
  "provider": "google",
  "login_url": "http://127.0.0.1:8000/accounts/google/login/?next=%2Fauth%2Fcallback",
  "next": "/auth/callback"
}
```

**404** — unknown or disabled provider. **503** — allauth unavailable.

#### `GET /api/auth/oauth/callback`

Requires an authenticated **Django session** (cookie from OAuth). Does not use `Authorization: Bearer`.

```http
GET /api/auth/oauth/callback
Cookie: sessionid=...
```

**200** (no lokdown 2FA)

```json
{
  "requires_2fa": false,
  "access_token": "<jwt>",
  "refresh_token": "<jwt>"
}
```

**200** (2FA required)

```json
{
  "requires_2fa": true,
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "totp_enabled": true,
  "passkey_enabled": false,
  "backup_codes_available": true
}
```

**401** — no session (OAuth not completed). **500** — failed to create `LoginSession`.

For cross-origin SPAs, prefer returning `session_id` / tokens from your own `auth_callback` view; this API route is for same-site clients and Swagger testing (`credentials: 'include'` on `fetch`).

### Admin helper (browser)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `auth/admin/2fa/passkey/options` | Django session | Challenge for admin passkey verify page |

---

## HTTP status codes (common cases)

| Code | When |
|------|------|
| 200 | Success |
| 400 | Invalid/expired `session_id`, missing fields, passkey without prior options |
| 401 | Bad password, bad 2FA token, SimpleJWT 2FA-required response on `/auth/token` |
| 403 | Not used on login; reserved for future self-only checks |
| 429 | Backup code rate limit exceeded |
| 500 | Failed to create session or generate WebAuthn options |

---

## Security notes

1. **HTTPS in production** — WebAuthn requires a trustworthy origin (`WEBAUTHN_ORIGIN` must match the browser URL).
2. **TOTP secrets at rest** — Encrypted with Fernet. Set `LOKDOWN_FERNET_KEY` (url-safe base64, 32 bytes) in production; otherwise derived from `SECRET_KEY`.
3. **Backup codes at rest** — Stored as salted hashes (Django password hasher). Plaintext codes are returned only once at generation via API/admin session flow.
4. **Session fixation** — `LoginSession` IDs are UUIDs, expire quickly, and cannot be reused after `is_authenticated=True`.
5. **Rate limiting** — Backup verification only (per IP); TOTP/passkey are not rate-limited on `auth/verify` beyond Django/infra limits.
6. **Verification before save** — TOTP secret and passkey credentials are persisted only after a successful verification step.
7. **Dependency supply chain** — Pin `django-lokdown` and its transitive dependencies in production (`pip-tools`, `uv lock`, etc.) and run [`pip-audit`](https://pypi.org/project/pip-audit/) on your lockfile in CI.
8. **`security_audit --cleanup`** — Dry-run by default; pass `--force` with `--cleanup` to delete expired sessions, old failed backup attempts, and stale passkeys.
9. **Social auth checks** — `lokdown.W003`/`W004` apply only when `"allauth"` is in `INSTALLED_APPS` and providers are configured; projects without OAuth can omit allauth entirely.

---

## Client checklist

- [ ] Set `LOKDOWN_FERNET_KEY` in production (generate with `Fernet.generate_key()` from `cryptography`).
- [ ] Include `path("api/", include("lokdown.urls"))` and call `override_admin_urls()`.
- [ ] Branch on `requires_2fa` after password login.
- [ ] For passkey login: call `passkey/options` before `verify`.
- [ ] Store JWT; refresh via `auth/token/refresh`.
- [ ] On 2FA setup: call `setup/totp` then `verify/totp` with only `totp_token` (pending secret is stored server-side).
- [ ] On passkey setup: pass `session_id` from setup into verify.
- [ ] Treat backup codes as single-use; handle 429 on backup attempts.
- [ ] Pin lokdown and transitive dependencies; run `pip-audit` in CI.
- [ ] (Optional) Add `LOKDOWN_ALLAUTH_BASE_APPS` + provider apps to `INSTALLED_APPS` before setting `SOCIALACCOUNT_PROVIDERS`.
- [ ] (Optional) `globals().update(get_allauth_recommended_settings())` and `MIDDLEWARE += get_lokdown_socialauth_middleware()`.
- [ ] (Optional) Mount `get_allauth_urlpatterns()` and implement `auth_callback` (or use `GET /api/auth/oauth/callback` from [OpenAPI OAuth endpoints](#external-provider-oauth)).
- [ ] (Optional) SPA: `GET /api/auth/oauth/{provider}/login` → redirect to `login_url` → `GET /api/auth/oauth/callback` with session cookie.
- [ ] (Optional) Regenerate `api_schema.json` after API changes: `python manage.py spectacular --file api_schema.json`.
- [ ] (Optional) Run `python manage.py check` after enabling social auth (expect `lokdown.W003`/`W004` if misconfigured).

---

## Internal extension points

To customize behaviour without duplicating controllers:

| Function | Module | Use |
|----------|--------|-----|
| `initiate_password_login` | `auth_flow_helper` | After password auth **or** OAuth callback (`request.user` already authenticated) |
| `bridge_oauth_session_to_lokdown` | `socialauth_controller` | Thin wrapper around `initiate_password_login` for OAuth bridge |
| `build_provider_login_url` | `socialauth_controller` | Build absolute `/accounts/<provider>/login/` URL for OpenAPI helpers |
| `verify_second_factor` | `auth_flow_helper` | Second factor during API login |
| `complete_login_with_tokens` | `auth_flow_helper` | Issue JWT after verification |
| `begin_totp_setup` / `complete_totp_setup` | `auth_flow_helper` | TOTP enrollment |
| `begin_passkey_registration` / `complete_passkey_registration` | `auth_flow_helper` | Passkey enrollment |
| `disable_user_2fa` | `auth_flow_helper` | Remove all factors |
| `verify_admin_second_factor` | `auth_flow_helper` | Admin HTML verify |

Serializers in `lokdown/serializers/` define stable OpenAPI schemas for each controller.
