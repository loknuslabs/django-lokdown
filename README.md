# Django Lokdown

A reusable Django package for Two-Factor Authentication (TOTP, WebAuthn passkeys), JWT APIs, admin 2FA, and optional social login (OAuth).

**Full documentation:** [lokdown/README.md](lokdown/README.md)

**Detailed authentication workflows:** [lokdown/docs/AUTHENTICATION.md](lokdown/docs/AUTHENTICATION.md)

## Quick install

```bash
pip install django-lokdown
```

```python
INSTALLED_APPS = ["lokdown", ...]
# urls.py: path("api/", include("lokdown.urls"))
```

## Local development

```bash
pip install -e ".[dev]"
cd example && python manage.py migrate && python manage.py runserver
```

See [lokdown/README.md — Local development](lokdown/README.md#local-development-example-project).
