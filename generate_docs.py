#!/usr/bin/env python3
"""
Script to generate API documentation for PennyPusher
Can be run locally or in CI environments
"""

import os
import sys
import subprocess
from pathlib import Path


def setup_environment():
    """Set up environment variables for documentation generation"""
    env_vars = {
        'SECRET_KEY': 'test-key-for-docs-generation',
        'DEBUG': 'True',
        'LOCAL_DB': 'True',
        'ALLOW_PUBLIC_REGISTRATION': 'False',
        'ADMIN_2FA_REQUIRED': 'False',
        'WEBAUTHN_RP_NAME': 'PennyPusher Local',
        'WEBAUTHN_ORIGIN': 'http://localhost:8000',
        'WEBAUTHN_RP_ID': 'localhost',
    }

    for key, value in env_vars.items():
        os.environ[key] = value


def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return False


def generate_documentation():
    """Generate complete API documentation"""
    print("🚀 Starting API documentation generation...")

    # Set up environment
    setup_environment()

    # Run database migrations
    if not run_command("python manage.py migrate", "Running database migrations"):
        return False

    # Generate OpenAPI schema
    if not run_command(
        "python manage.py spectacular --file api_schema.json --format openapi-json", "Generating OpenAPI schema"
    ):
        return False

    # Generate HTML documentation
    if not run_command("python docs/convert_to_html.py", "Generating HTML documentation"):
        return False

    # Create docs directory if it doesn't exist
    docs_dir = Path("docs")
    docs_dir.mkdir(exist_ok=True)

    # Move files to docs directory
    files_to_move = ["api_schema.json", "api_documentation.html", "convert_to_html.py"]
    for file in files_to_move:
        if Path(file).exists():
            subprocess.run(f"mv {file} docs/", shell=True, check=True)
            print(f"📁 Moved {file} to docs/")

    # Create README for docs directory
    readme_content = """# API Documentation

This directory contains automatically generated API documentation for the PennyPusher API.

## Files

- `api_schema.json` - Complete OpenAPI specification
- `api_documentation.html` - Formatted HTML documentation
- `convert_to_html.py` - Script used to generate the HTML documentation

## Usage

Open `api_documentation.html` in your browser to view the complete API documentation.
You can also print it to PDF using your browser's print function (Cmd+P / Ctrl+P).

The OpenAPI schema can also be imported into tools like:
- [Postman](https://www.postman.com/)
- [Swagger Editor](https://editor.swagger.io/)
- [OpenAPI Generator](https://openapi-generator.tech/)

## Regeneration

This documentation is automatically regenerated on pull requests via GitHub Actions.
To manually regenerate:

```bash
python generate_docs.py
```

Generated on: {date}
""".format(
        date=subprocess.run("date", shell=True, capture_output=True, text=True).stdout.strip()
    )

    with open("docs/README.md", "w") as f:
        f.write(readme_content)

    print("📝 Created docs/README.md")

    print("🎉 Documentation generation completed successfully!")
    print("📁 Files generated:")
    print("   - api_schema.json")
    print("   - api_documentation.html")
    print("   - docs/ (directory with all files)")

    return True


if __name__ == "__main__":
    success = generate_documentation()
    sys.exit(0 if success else 1)
