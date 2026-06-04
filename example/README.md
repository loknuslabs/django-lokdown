# Local example project

This directory is **not** published to PyPI. It runs django-lokdown from the repository for local development and manual testing.

## Setup

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run the dev server

```bash
cd example
python manage.py migrate
python manage.py runserver
```

- Home: http://127.0.0.1:8000/
- Admin (with 2FA): http://127.0.0.1:8000/admin/ (user `admin` / `password` after migrate)
- API docs: http://127.0.0.1:8000/api/schema/swagger-ui/

You can also use the root helper script:

```bash
./scripts/runserver.sh
```

## System checks

This example includes **lokdown only** (no django-allauth in `INSTALLED_APPS`). That matches a password + 2FA JWT setup:

```bash
python manage.py check
```

Should report no issues. Social-auth lokdown checks (`lokdown.W003`, `lokdown.W004`) are skipped until you add allauth and configure providers.

## Optional: enable social login in the example

To try OAuth locally, extend `example/devsite/settings.py` and `urls.py` using the guide in [lokdown/docs/AUTHENTICATION.md](../lokdown/docs/AUTHENTICATION.md#social-login-django-allauth):

1. Add `LOKDOWN_ALLAUTH_BASE_APPS` and provider apps (e.g. `dummy` or `google`) to `INSTALLED_APPS`.
2. `globals().update(get_allauth_recommended_settings())` and append `get_lokdown_socialauth_middleware()` to `MIDDLEWARE`.
3. Mount `get_allauth_urlpatterns()` and a named `auth_callback` URL.
4. Set `SOCIALACCOUNT_PROVIDERS` (or use the `dummy` provider for tests without real OAuth credentials).
5. Run `python manage.py migrate sites`.

Do not set `SOCIALACCOUNT_PROVIDERS` until allauth apps are in `INSTALLED_APPS`.

After OAuth works, implement `auth_callback` to call `initiate_password_login(request.user, request)` and hand off `session_id` or JWTs to your SPA — see [Login with external provider](../lokdown/docs/AUTHENTICATION.md#api-workflow-login-with-external-provider-oauth).
