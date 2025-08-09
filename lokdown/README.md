# Django Security App

A reusable Django app that provides comprehensive Two-Factor Authentication (2FA) functionality with WebAuthn passkey support and enhanced admin integration.

## Features

- **TOTP (Time-based One-Time Password)**: Compatible with authenticator apps
- **WebAuthn Passkeys**: Modern passwordless authentication
- **Backup Codes**: One-time use backup codes for account recovery
- **Rate Limiting**: Strict rate limiting for security
- **Admin Dashboard**: Comprehensive security monitoring with dark mode support
- **CLI Tools**: Security audit and management commands
- **Streamlined UX**: One-click 2FA setup and verification flows
- **Backup Code Management**: Visual display and download functionality for regenerated codes

## Installation

### Basic Setup

1. Add the security app to your Django project:
```python
# settings.py
INSTALLED_APPS = [
    # ... other apps
    'lokdown',
]
```

2. Include the security URLs in your main URL configuration:

```python
# urls.py
from django.urls import path, include
from lokdown.admin_url_override import override_admin_urls

urlpatterns = [
    # ... your other URLs
    path('admin/', admin.site.urls),
    path('api/', include('lokdown.urls')),
    # ... more URLs
]

# Override admin URLs with 2FA support if enabled
urlpatterns = override_admin_urls(urlpatterns)
```

3. Run migrations:
```bash
python manage.py makemigrations lokdown
python manage.py migrate
```

### Complete Setup with Admin 2FA

For a complete setup with admin 2FA enabled:

1. **Settings Configuration**:
```python
# settings.py
INSTALLED_APPS = [
    # ... other apps
    'lokdown',
]

# WebAuthn Configuration
WEBAUTHN_RP_ID = 'yourdomain.com'
WEBAUTHN_RP_NAME = 'Your App Name'
WEBAUTHN_ORIGIN = 'https://yourdomain.com'

# 2FA Configuration
ADMIN_2FA_REQUIRED = True  # Enable admin 2FA
BACKUP_CODE_RATE_LIMIT = 10
TWOFA_SESSION_TIMEOUT = 10
BACKUP_CODES_COUNT = 8
BACKUP_CODE_LENGTH = 10
```

2. **URL Configuration**:

```python
# urls.py
from django.urls import path, include
from django.contrib import admin
from lokdown.admin_url_override import override_admin_urls

urlpatterns = [
    # Your app URLs
    path('api/', include('lokdown.urls')),

    # Admin URLs (will be overridden if 2FA is enabled)
    path('admin/', admin.site.urls),
]

# Override admin URLs with 2FA support
urlpatterns = override_admin_urls(urlpatterns)
```

3. **Environment Variables** (optional):
```bash
# .env or environment variables
ADMIN_2FA_REQUIRED=True
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_RP_NAME=Your App Name
WEBAUTHN_ORIGIN=https://yourdomain.com
BACKUP_CODE_RATE_LIMIT=10
TWOFA_SESSION_TIMEOUT=10
BACKUP_CODES_COUNT=8
BACKUP_CODE_LENGTH=10
```

## Configuration

### Required Settings

Add these settings to your Django settings file:

```python
# settings.py

# WebAuthn Configuration
WEBAUTHN_RP_ID = 'localhost'  # Your domain
WEBAUTHN_RP_NAME = 'Your App Name'
WEBAUTHN_ORIGIN = 'http://localhost:8000'  # Your origin

# Security Settings
SECURE_SSL_REDIRECT = not DEBUG  # Redirect to HTTPS in production
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
```

### Optional Settings

```python
# settings.py

# Rate Limiting (optional, uses django-ratelimit)
RATELIMIT_USE_CACHE = 'default'

# Security Dashboard Refresh (optional)
SECURITY_DASHBOARD_REFRESH_INTERVAL = 30000  # milliseconds
```

### Environment Variables

The security app supports configuration via environment variables:

```python
# settings.py
import os

# WebAuthn Configuration
WEBAUTHN_RP_ID = os.environ.get('WEBAUTHN_RP_ID', 'localhost')
WEBAUTHN_RP_NAME = os.environ.get('WEBAUTHN_RP_NAME', 'Your App Name')
WEBAUTHN_ORIGIN = os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:8000')

# 2FA Configuration
BACKUP_CODE_RATE_LIMIT = int(os.environ.get('BACKUP_CODE_RATE_LIMIT', '10'))
TWOFA_SESSION_TIMEOUT = int(os.environ.get('TWOFA_SESSION_TIMEOUT', '10'))
BACKUP_CODES_COUNT = int(os.environ.get('BACKUP_CODES_COUNT', '8'))
BACKUP_CODE_LENGTH = int(os.environ.get('BACKUP_CODE_LENGTH', '10'))
```

#### Environment Variable Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBAUTHN_RP_ID` | `localhost` | Your domain for WebAuthn |
| `WEBAUTHN_RP_NAME` | `Your App Name` | Your application name |
| `WEBAUTHN_ORIGIN` | `http://localhost:8000` | Your application origin |
| `BACKUP_CODE_RATE_LIMIT` | `10` | Backup code attempts per minute |
| `TWOFA_SESSION_TIMEOUT` | `10` | 2FA session timeout in minutes |
| `BACKUP_CODES_COUNT` | `8` | Number of backup codes to generate |
| `BACKUP_CODE_LENGTH` | `10` | Length of each backup code |
| `ADMIN_2FA_REQUIRED` | `False` | Require 2FA for admin users |

## API Endpoints

### Authentication
- `POST /api/auth/login` - Initialize login with 2FA check
- `POST /api/auth/verify` - Complete login with 2FA verification
- `POST /api/auth/2fa/verify/backup` - Dedicated backup code verification

### 2FA Management
- `POST /api/auth/2fa/setup/totp` - Setup TOTP authentication
- `POST /api/auth/2fa/verify/totp` - Verify TOTP setup
- `POST /api/auth/2fa/passkey/setup` - Setup WebAuthn passkey
- `POST /api/auth/2fa/passkey/verify` - Verify passkey setup
- `GET /api/auth/2fa/status` - Get current 2FA status
- `POST /api/auth/2fa/disable` - Disable 2FA for user
- `GET /api/auth/2fa/passkey/credentials` - Get passkey credentials
- `DELETE /api/auth/2fa/passkey/remove` - Remove passkey credential

## Django Admin

The security app provides enhanced admin models with comprehensive management capabilities:

### Admin Models

- **UserTwoFactorAuth**: Manage 2FA settings with security dashboard
- **PasskeyCredential**: View and manage WebAuthn passkey credentials
- **BackupCodes**: Manage and regenerate backup codes with visual display
- **LoginSession**: Monitor active login sessions
- **FailedBackupCodeAttempt**: Track failed backup code attempts

Access the security admin at `/admin/security/`

### Admin 2FA Integration

When `ADMIN_2FA_REQUIRED` is enabled, the security app automatically overrides Django's admin interface with a streamlined experience:

#### **First-Time Setup Flow**
1. **Admin Login**: User logs in with username/password
2. **2FA Selection**: User chooses between TOTP or Passkey (one-click selection)
3. **Setup Process**: 
   - **TOTP**: QR code generation with verification-before-save
   - **Passkey**: WebAuthn registration with device prompts
4. **Backup Codes**: Automatic generation and display with download options
5. **Completion**: Redirect to admin dashboard

#### **Subsequent Login Flow**
1. **Admin Login**: User logs in with username/password
2. **2FA Verification**: User selects verification method (one-click)
3. **Authentication**:
   - **TOTP**: Enter 6-digit code
   - **Passkey**: Automatic device prompt (no extra button clicks)
   - **Backup Code**: Enter backup code with rate limiting
4. **Access**: Redirect to admin dashboard

#### **Key Features**
- **One-Click Selection**: No confirmation buttons for 2FA method selection
- **Verification-Before-Save**: TOTP is only saved after successful verification
- **Automatic Passkey**: Passkey authentication triggers immediately on selection
- **Backup Code Management**: Visual display and download for regenerated codes
- **Dark Mode Support**: All templates support light/dark themes
- **Overwrite Support**: Replace existing 2FA methods through admin interface
- **Security Dashboard**: Comprehensive monitoring with statistics

#### **Admin Actions**
- **Regenerate Backup Codes**: Bulk regeneration with visual display
- **Disable 2FA**: Remove all 2FA methods for selected users
- **Security Audit**: CLI commands for security monitoring
- **Export Data**: Download security reports and logs

### Easy Integration

To enable admin 2FA in any Django project, simply add this to your `urls.py`:

```python
from lokdown.admin_url_override import override_admin_urls

urlpatterns = [
    # ... your other URLs
    path('admin/', admin.site.urls),
    # ... more URLs
]

# Override admin URLs with 2FA support if enabled
urlpatterns = override_admin_urls(urlpatterns)
```

The security app will automatically:
- Check if `ADMIN_2FA_REQUIRED` is True
- Override the admin URLs with 2FA support
- Provide all necessary templates and views
- Handle the complete 2FA flow for administrators

## Management Commands

```bash
# Security audit
python manage.py security_audit --days 30 --export --cleanup

# Clean up old data
python manage.py security_audit --cleanup
```

## Models

### UserTimeBasedOneTimePasswords
Stores TOTP settings for users:
- `user`: OneToOneField to User
- `totp_secret`: CharField for TOTP secret (only when TOTP is enabled)
- `created_at`: DateTimeField for creation timestamp
- `updated_at`: DateTimeField for last update
- `last_used`: DateTimeField for last TOTP usage

### PasskeyCredential
Stores WebAuthn passkey credentials:
- `user`: ForeignKey to User
- `credential_id`: Unique credential identifier
- `public_key`: TextField for public key
- `sign_count`: BigInteger for signature count
- `transports`: JSONField for supported transports
- `rp_id`: CharField for relying party ID
- `user_handle`: CharField for user handle
- `created_at`: DateTimeField for creation timestamp
- `last_used`: DateTimeField for last usage

### BackupCodes
Stores backup codes for 2FA users:
- `user`: OneToOneField to User
- `codes`: JSONField for backup codes
- `created_at`: DateTimeField for creation timestamp
- `updated_at`: DateTimeField for last update

### LoginSession
Tracks login sessions for 2FA flow:
- `user`: ForeignKey to User
- `session_id`: Unique session identifier
- `is_authenticated`: Boolean for authentication status
- `requires_2fa`: Boolean for 2FA requirement
- `totp_verified`: Boolean for TOTP verification
- `passkey_verified`: Boolean for passkey verification
- `challenge`: TextField for WebAuthn challenge
- `expires_at`: DateTimeField for session expiration
- `ip_address`: GenericIPAddressField for IP tracking
- `user_agent`: TextField for user agent

### FailedBackupCodeAttempt
Tracks failed backup code attempts:
- `user`: ForeignKey to User
- `ip_address`: GenericIPAddressField for IP tracking
- `user_agent`: TextField for user agent
- `attempted_code`: CharField for attempted code (partial)
- `created_at`: DateTimeField for attempt timestamp

### SecurityDashboard
Dummy model for security dashboard admin page.

## Customization

### Custom User Model
If you're using a custom user model, update the foreign key references:

```python
# settings.py
AUTH_USER_MODEL = 'your_app.YourUserModel'
```

### Custom Templates
Override the security templates:

```python
# settings.py
TEMPLATES = [
    {
        'DIRS': [BASE_DIR / 'templates'],
        # ... other settings
    },
]
```

Create custom templates in your project:
- `templates/admin/security_dashboard.html`
- `templates/admin/backup_codes_display.html`
- `security/templates/2fa_setup.html`
- `security/templates/2fa_verify.html`

### Custom Settings
Extend the security app settings:

```python
# settings.py
SECURITY_APP_CONFIG = {
    'BACKUP_CODES_COUNT': 10,
    'SESSION_TIMEOUT_MINUTES': 10,
    'RATE_LIMIT_ATTEMPTS': 10,
    'RATE_LIMIT_PERIOD': '1m',
}
```

## Security Considerations

1. **Rate Limiting**: Backup codes have strict rate limiting (10 attempts per minute per IP)
2. **Failed Attempt Logging**: All failed attempts are logged for monitoring
3. **Session Management**: Login sessions expire after 10 minutes
4. **Backup Code Security**: Backup codes are single-use and removed after use
5. **HTTPS Required**: WebAuthn requires HTTPS in production
6. **Verification-Before-Save**: TOTP is only saved after successful verification
7. **One-Click Flows**: Streamlined UX reduces user friction while maintaining security
8. **Dark Mode Support**: Consistent theming across all interfaces

## Recent Improvements

### **Streamlined 2FA Setup**
- **One-Click Selection**: No confirmation buttons for 2FA method selection
- **Automatic Progression**: Form submits automatically after method selection
- **Loading States**: Visual feedback during setup process
- **Verification-Before-Save**: TOTP only saved after successful verification

### **Enhanced Passkey Experience**
- **Automatic Authentication**: Passkey triggers immediately on selection
- **Native Prompts**: Uses browser's built-in WebAuthn UI
- **No Extra Buttons**: Eliminates unnecessary confirmation steps
- **Error Handling**: Graceful fallback to other methods

### **Backup Code Management**
- **Visual Display**: Regenerated codes shown immediately after generation
- **Download Options**: TXT and CSV download formats
- **Auto-Download**: Automatic TXT download after 5 seconds
- **Security Warnings**: Clear instructions for secure storage
- **Dark Mode Support**: Consistent theming with admin interface

### **Admin Interface Improvements**
- **Overwrite Support**: Replace existing 2FA methods through admin
- **Bulk Operations**: Regenerate backup codes for multiple users
- **Security Dashboard**: Comprehensive monitoring with statistics
- **Responsive Design**: Works on all device sizes
- **Keyboard Shortcuts**: Quick download options (Ctrl+S, Ctrl+D)

## Dependencies

- `django-ratelimit` - For rate limiting
- `pyotp` - For TOTP generation
- `webauthn` - For WebAuthn support
- `qrcode` - For TOTP QR code generation
- `Pillow` - For QR code image processing

## License

This app is part of the PennyPusher project and follows the same license terms. 