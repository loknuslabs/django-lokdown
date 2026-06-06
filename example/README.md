# Example project

Local Django project for testing django-lokdown (not published to PyPI).

**Full documentation:** [../lokdown/README.md](../lokdown/README.md)

- [Local development](../lokdown/README.md#local-development-example-project)
- [User API keys](../lokdown/README.md#user-api-keys)
- [OAuth setup](../lokdown/README.md#social-login-oauth)
- [SPA-only frontend](../lokdown/docs/AUTHENTICATION.md#spa-only-frontend-no-django-html-templates)

## Quick start

```bash
pip install -e ".[dev]"
cd example
python manage.py migrate
python manage.py runserver
```

Default admin: `admin` / `password`

Enable API keys in the example project:

```bash
LOKDOWN_API_KEYS_ENABLED=true python manage.py runserver
```
