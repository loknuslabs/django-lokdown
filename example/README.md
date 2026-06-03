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
