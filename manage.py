#!/usr/bin/env python
"""Convenience entrypoint that runs the example project manage.py."""
import os
import sys
from pathlib import Path


def main():
    example_dir = Path(__file__).resolve().parent / "example"
    sys.path.insert(0, str(example_dir))
    os.chdir(example_dir)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "devsite.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Install with 'pip install -e \".[dev]\"' from the repo root."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
