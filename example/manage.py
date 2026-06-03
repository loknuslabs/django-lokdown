#!/usr/bin/env python
"""Django management utility for the local example project."""
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "devsite.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Install the package with " "'pip install -e \".[dev]\"' from the repository root."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
