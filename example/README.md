# Local example project

This directory is **not** published to PyPI. It runs django-lokdown from the repository for local development and manual testing, including **Google and GitHub OAuth** via lokdown’s allauth integration.

## Setup

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### OAuth credentials (Google + GitHub)

```bash
cp example/.env.example example/.env
# Edit example/.env with your client IDs and secrets
set -a && source example/.env && set +a   # bash/zsh
```

Register these **authorized redirect URIs** in each provider:

| Provider | Redirect URI |
|----------|----------------|
| Google | `http://127.0.0.1:8000/accounts/google/login/callback/` |
| GitHub | `http://127.0.0.1:8000/accounts/github/login/callback/` |

Use `127.0.0.1` consistently (not `localhost`) unless you also register `localhost` variants.

Providers are enabled only when both `CLIENT_ID` and `SECRET` are set for that provider. Without env vars, the example still runs; the home page shows a reminder to configure OAuth.

## Run the dev server

```bash
cd example
python manage.py migrate
python manage.py migrate sites
python manage.py runserver
```

- Home: http://127.0.0.1:8000/ — links to Google/GitHub sign-in when configured
- OAuth callback: http://127.0.0.1:8000/auth/callback — issues lokdown JWT or `session_id` for 2FA ([workflow](../lokdown/docs/AUTHENTICATION.md#api-workflow-login-with-external-provider-oauth))
- Admin (with 2FA): http://127.0.0.1:8000/admin/ (user `admin` / `password` after migrate)
- API docs: http://127.0.0.1:8000/api/schema/swagger-ui/

You can also use the root helper script:

```bash
./scripts/runserver.sh
```

## OAuth login flow

### Via home page (browser)

1. Open http://127.0.0.1:8000/ and choose **Sign in with Google** or **Sign in with GitHub**.
2. Complete OAuth; you are redirected to `/auth/callback` with a Django session.
3. The HTML callback page shows JWTs or a lokdown `session_id` (if 2FA is enabled).

### Via documented API (Swagger / `api_schema.json`)

Same flow, but discover and test endpoints from OpenAPI:

1. **List providers** — `GET /api/auth/oauth/providers` (optional `?next=/auth/callback`)
2. **Start OAuth** — `GET /api/auth/oauth/google/login` → copy `login_url` into the browser
3. **After OAuth** — `GET /api/auth/oauth/callback` with the session cookie (`credentials: 'include'` in `fetch`, or try in Swagger if the session is active)
4. **If `requires_2fa: true`** — `POST /api/auth/verify` with `session_id` (tag **Authentication**)

| OpenAPI path | Operation (example) | Auth |
|--------------|---------------------|------|
| `/api/auth/oauth/providers` | `auth_oauth_providers_retrieve` | None |
| `/api/auth/oauth/{provider}/login` | `auth_oauth_login_retrieve` | None |
| `/api/auth/oauth/callback` | `auth_oauth_callback_retrieve` | Django session |

`/accounts/*` routes from django-allauth are **not** in `api_schema.json` because they are HTML/redirect views, not DRF. The API helpers return the same `login_url` you would use manually.

**Regenerate schema** after changing controllers:

```bash
cd example
python manage.py spectacular --file api_schema.json
```

- Swagger UI: http://127.0.0.1:8000/api/schema/swagger-ui/
- Committed snapshot: [api_schema.json](api_schema.json)

Append `?format=json` on `/auth/callback` for raw JSON from the non-API HTML callback.

## System checks

```bash
cd example
python manage.py check
```

With OAuth env vars set, lokdown expects `SITE_ID` and `SOCIALACCOUNT_ADAPTER` (configured in `devsite/settings.py`).

## Configuration reference

| Variable | Purpose |
|----------|---------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth app |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth app |
| `SOCIALACCOUNT_LOGIN_AUTO_REDIRECT_PROVIDER` | Optional: `google` or `github` to auto-redirect `/accounts/login/` |

| File | Role |
|------|------|
| `devsite/settings.py` | allauth apps, middleware, `SOCIALACCOUNT_PROVIDERS` |
| `devsite/socialauth_settings.py` | OAuth credentials from env |
| `devsite/auth_views.py` | HTML `/auth/callback` |
| `devsite/urls.py` | `get_allauth_urlpatterns()` + `include(lokdown.urls)` |
| `lokdown/control/socialauth_controller.py` | `/api/auth/oauth/*` (published with lokdown) |

Further detail: [lokdown/docs/AUTHENTICATION.md](../lokdown/docs/AUTHENTICATION.md) — [OpenAPI / api_schema.json](../lokdown/docs/AUTHENTICATION.md#openapi--swagger-api_schemajson), [OAuth workflow](../lokdown/docs/AUTHENTICATION.md#api-workflow-login-with-external-provider-oauth).
