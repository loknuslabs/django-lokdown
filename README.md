# Django Lokdown - Two-Factor Authentication (2FA) System

A comprehensive Django application providing robust Two-Factor Authentication (2FA) with support for TOTP and WebAuthn Passkeys.

## Overview

The Django Lokdown 2FA system supports two authentication methods:
1. **TOTP (Time-based One-Time Password)** - Compatible with authenticator apps like Google Authenticator, Authy, etc.
2. **WebAuthn Passkeys** - Modern passwordless authentication using WebAuthn standard, compatible with:
   - YubiKeys and other hardware security keys
   - Apple Keychain (iOS/macOS)
   - Google Password Manager
   - Windows Hello
   - Any WebAuthn-compliant authenticator

## Project Structure

```
django-lokdown/
├── configuration/           # Django project settings
│   ├── settings.py         # Main configuration
│   ├── urls.py            # URL routing
│   └── wsgi.py            # WSGI application
├── lokdown/               # Main 2FA application
│   ├── admin.py           # Django admin interface
│   ├── admin_auth.py      # Admin authentication logic
│   ├── admin_url_override.py  # Admin URL customization
│   ├── apps.py            # Django app configuration
│   ├── models.py          # Database models
│   ├── serializers.py     # DRF serializers
│   ├── urls.py           # Application URLs
│   ├── views.py          # API views
│   ├── control/          # Authentication controllers
│   │   ├── backup_code_controller.py
│   │   ├── passkey_controller.py
│   │   ├── token_views.py
│   │   └── totp_controller.py
│   ├── helpers/          # Utility helpers
│   │   ├── backup_codes_helper.py
│   │   ├── common_helper.py
│   │   ├── passkey_helper.py
│   │   ├── session_helper.py
│   │   ├── totp_helper.py
│   │   └── twofa_helper.py
│   ├── management/       # Django management commands
│   │   └── commands/
│   │       └── security_audit.py
│   ├── migrations/       # Database migrations
│   ├── static/          # Static files (CSS, JS)
│   └── templates/       # HTML templates
├── tester/              # Test application
├── manage.py           # Django management script
├── requirements.txt    # Python dependencies
└── pyproject.toml     # Project metadata
```

## Recent Admin Authentication Improvements

### Streamlined User Experience

The admin 2FA system has been significantly improved to provide a seamless, one-click experience:

#### **One-Click 2FA Setup**
- **No Confirmation Buttons**: Users simply click their preferred 2FA method (TOTP or Passkey)
- **Automatic Progression**: Form submits automatically after method selection
- **Loading States**: Visual feedback during the setup process
- **Verification-Before-Save**: TOTP is only saved to the database after successful verification

#### **Enhanced Passkey Experience**
- **Automatic Authentication**: Passkey authentication triggers immediately when selected
- **Native Browser Prompts**: Uses the browser's built-in WebAuthn UI
- **No Extra Buttons**: Eliminates unnecessary confirmation steps
- **Graceful Error Handling**: Falls back to other methods if passkey fails

#### **Backup Code Management**
- **Visual Display**: Regenerated backup codes are shown immediately after generation
- **Download Options**: TXT and CSV download formats available
- **Auto-Download**: Automatic TXT download after 5 seconds
- **Security Warnings**: Clear instructions for secure storage
- **Dark Mode Support**: Consistent theming with the admin interface

### Admin Interface Features

#### **Security Dashboard**
- **Real-time Statistics**: 2FA adoption rates, active sessions, failed attempts
- **Security Score**: Calculated based on adoption and threat levels
- **Quick Actions**: Direct links to manage different security aspects
- **Dark Mode Support**: Adapts to user's system preferences

#### **Backup Code Management**
- **Bulk Regeneration**: Regenerate backup codes for multiple users at once
- **Visual Display**: See new codes immediately after regeneration
- **Download Formats**: TXT and CSV options for different use cases
- **Security Notices**: Clear warnings about secure storage

#### **Admin Actions**
- **Overwrite Support**: Replace existing 2FA methods through admin interface
- **Bulk Operations**: Manage multiple users' 2FA settings
- **Security Audit**: CLI commands for comprehensive security monitoring
- **Export Data**: Download security reports and logs

### User Flow Examples

#### **First-Time Admin Setup**
1. **Login**: Admin logs in with username/password
2. **2FA Selection**: Clicks TOTP or Passkey (one-click)
3. **Setup Process**:
   - **TOTP**: QR code appears, admin scans with authenticator app, enters code for verification
   - **Passkey**: Browser prompts for device authentication (fingerprint, face ID, PIN)
4. **Backup Codes**: Automatically generated and displayed with download options
5. **Completion**: Redirected to admin dashboard

#### **Subsequent Admin Login**
1. **Login**: Admin logs in with username/password
2. **2FA Verification**: Clicks preferred verification method (one-click)
3. **Authentication**:
   - **TOTP**: Enter 6-digit code from authenticator app
   - **Passkey**: Automatic device prompt (no extra clicks)
   - **Backup Code**: Enter backup code with rate limiting
4. **Access**: Redirected to admin dashboard

### Technical Improvements

#### **Verification-Before-Save Pattern**
```python
# TOTP is only saved after successful verification
if totp.verify(totp_code):
    two_fa.totp_secret = secret
    two_fa.save()
    # Generate backup codes...
else:
    # Show error and allow retry
```

#### **Automatic Passkey Trigger**
```javascript
// Passkey authentication triggers immediately on selection
if (method === 'passkey') {
    setTimeout(function() {
        authenticateWithPasskey();
    }, 500);
}
```

#### **Backup Code Display**
```python
# Store codes in session for immediate display
request.session['regenerated_backup_codes'] = new_codes
request.session['regenerated_backup_codes_count'] = updated
return redirect('/api/admin/backup-codes/display')
```

### Security Enhancements

1. **Verification-Before-Save**: TOTP secrets are only stored after successful verification
2. **One-Click Flows**: Streamlined UX reduces user friction while maintaining security
3. **Dark Mode Support**: Consistent theming across all interfaces
4. **Rate Limiting**: Strict rate limiting for backup codes and failed attempts
5. **Session Management**: Secure session handling with automatic cleanup
6. **Error Handling**: Graceful fallbacks for failed authentication attempts

## API Endpoints

### Authentication Flow

#### 1. Login Initiation
**Endpoint:** `POST /api/auth/login`
**Description:** Start the login process. If 2FA is enabled, returns session info for verification.

**Request:**
```json
{
    "username": "your_username",
    "password": "your_password"
}
```

**Response (No 2FA):**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "requires_2fa": false
}
```

**Response (2FA Required):**
```json
{
    "session_id": "abc123def456...",
    "requires_2fa": true,
    "totp_enabled": true,
    "passkey_enabled": true,
    "expires_at": "2024-01-15T10:30:00Z"
}
```

#### 2. 2FA Verification
**Endpoint:** `POST /api/auth/verify`
**Description:** Complete login by verifying 2FA token.

**Request (TOTP):**
```json
{
    "session_id": "abc123def456...",
    "totp_token": "123456"
}
```

**Request (Passkey):**
```json
{
    "session_id": "abc123def456...",
    "passkey_response": {
        "id": "credential_id",
        "response": {
            "authenticatorData": "base64_encoded_data",
            "clientDataJSON": "base64_encoded_data",
            "signature": "base64_encoded_signature"
        }
    }
}
```

**Request (Backup Code):**
```json
{
    "session_id": "abc123def456...",
    "backup_code": "ABC123DEF4"
}
```

**Response:**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "requires_2fa": false
}
```

### 2FA Setup

#### 1. Setup TOTP
**Endpoint:** `POST /api/auth/2fa/setup/totp`
**Description:** Generate TOTP secret and QR code for authenticator app setup.

**Response:**
```json
{
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "backup_codes": ["ABC123DEF4", "GHI567JKL8", "MNO901PQR2", ...]
}
```

#### 2. Verify TOTP Setup
**Endpoint:** `POST /api/auth/2fa/verify/totp`
**Description:** Verify TOTP token to complete setup.

**Request:**
```json
{
    "token": "123456"
}
```

#### 3. Setup WebAuthn Passkey
**Endpoint:** `POST /api/auth/2fa/setup/passkey`
**Description:** Generate challenge for WebAuthn passkey registration.

**Response:**
```json
{
    "challenge": "base64_encoded_challenge",
    "rp_id": "localhost",
    "rp_name": "Django Lokdown",
    "user_id": "1",
    "user_name": "username",
    "user_display_name": "John Doe",
    "pub_key_cred_params": [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257}
    ],
    "authenticator_selection": {
        "user_verification": "preferred",
        "resident_key": "preferred"
    },
    "timeout": 60000
}
```

#### 4. Verify WebAuthn Passkey Setup
**Endpoint:** `POST /api/auth/2fa/verify/passkey`
**Description:** Verify WebAuthn passkey registration response.

**Request:**
```json
{
    "credential_id": "base64_encoded_credential_id",
    "authenticator_data": "base64_encoded_data",
    "client_data_json": "base64_encoded_data",
    "signature": "base64_encoded_signature"
}
```

### 2FA Management

#### 1. Get 2FA Status
**Endpoint:** `GET /api/auth/2fa/status`
**Description:** Get current 2FA settings for user.

**Response:**
```json
{
    "is_enabled": true,
    "totp_enabled": true,
    "passkey_enabled": true,
    "created_at": "2024-01-15T10:00:00Z",
    "updated_at": "2024-01-15T10:00:00Z"
}
```

#### 2. Disable 2FA
**Endpoint:** `POST /api/auth/2fa/disable`
**Description:** Disable 2FA for user.

**Response:**
```json
{
    "message": "2FA disabled successfully"
}
```

#### 3. Get Passkey Credentials
**Endpoint:** `GET /api/auth/2fa/passkey/credentials`
**Description:** Get list of registered passkey credentials.

**Response:**
```json
[
    {
        "id": 1,
        "credential_id": "base64_encoded_id",
        "sign_count": 5,
        "transports": ["usb", "nfc"],
        "rp_id": "localhost",
        "created_at": "2024-01-15T10:00:00Z",
        "last_used": "2024-01-15T10:30:00Z"
    }
]
```

#### 4. Remove Passkey Credential
**Endpoint:** `DELETE /api/auth/2fa/passkey/remove?credential_id=abc123`
**Description:** Remove a specific passkey credential.

#### 5. Verify Backup Code (Dedicated Endpoint)
**Endpoint:** `POST /api/auth/2fa/verify/backup`
**Description:** Verify backup code with strict rate limiting (10 attempts per minute per IP).

**Request:**
```json
{
    "session_id": "abc123def456...",
    "backup_code": "ABC123DEF4"
}
```

**Response:**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "requires_2fa": false,
    "message": "Backup code verified successfully"
}
```

**Rate Limiting:** This endpoint is strictly rate-limited to 10 attempts per minute per IP address. Failed attempts are logged for security monitoring.

## Usage Examples

### Setting up TOTP 2FA

1. **Setup TOTP:**
```bash
curl -X POST http://localhost:8000/api/auth/2fa/setup/totp \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

2. **Scan QR code** with your authenticator app (Google Authenticator, Authy, etc.)

3. **Verify setup:**
```bash
curl -X POST http://localhost:8000/api/auth/2fa/verify/totp \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"token": "123456"}'
```

### Setting up WebAuthn Passkeys

1. **Setup Passkey:**
```bash
curl -X POST http://localhost:8000/api/auth/2fa/setup/passkey \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

2. **Use the response** to register your passkey with the WebAuthn API in your frontend:
```javascript
// Frontend JavaScript example
const options = await fetch('/api/auth/2fa/setup/passkey', {
    method: 'POST',
    headers: {
        'Authorization': 'Bearer YOUR_ACCESS_TOKEN',
        'Content-Type': 'application/json'
    }
}).then(r => r.json());

// Create credentials
const credential = await navigator.credentials.create({
    publicKey: options
});

// Send to server for verification
await fetch('/api/auth/2fa/verify/passkey', {
    method: 'POST',
    headers: {
        'Authorization': 'Bearer YOUR_ACCESS_TOKEN',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        credential_id: credential.id,
        authenticator_data: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
        client_data_json: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
        signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
    })
});
```

### Login with 2FA

1. **Initiate login:**
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}'
```

2. **If 2FA is required**, verify with your chosen method:

   **TOTP:**
   ```bash
   curl -X POST http://localhost:8000/api/auth/verify \
     -H "Content-Type: application/json" \
     -d '{"session_id": "abc123...", "totp_token": "123456"}'
   ```

   **Passkey:**
   ```bash
   curl -X POST http://localhost:8000/api/auth/verify \
     -H "Content-Type: application/json" \
     -d '{"session_id": "abc123...", "passkey_response": {...}}'
   ```

   **Backup Code:**
   ```bash
   curl -X POST http://localhost:8000/api/auth/verify \
     -H "Content-Type: application/json" \
     -d '{"session_id": "abc123...", "backup_code": "ABC123DEF4"}'
   ```

## Supported Passkey Authenticators

The WebAuthn implementation supports all modern passkey authenticators:

### Hardware Security Keys
- **YubiKey** (all models)
- **Feitian** security keys
- **Solo** security keys
- **Titan** security keys
- Any FIDO2-compliant security key

### Platform Authenticators
- **Apple Keychain** (iOS 15+, macOS 12+)
- **Google Password Manager** (Android, Chrome)
- **Windows Hello** (Windows 10+)
- **Touch ID** (macOS)
- **Face ID** (iOS)

### Browser Support
- **Chrome** 67+
- **Firefox** 60+
- **Safari** 13+
- **Edge** 18+

## Security Features

### Session Management
- Login sessions expire after 10 minutes
- Sessions are tied to IP address and user agent
- Failed verification attempts are logged

### Backup Codes
- 8 backup codes are generated during TOTP setup
- Each backup code can only be used once
- Backup codes are automatically removed after use

### Passkey Security
- Supports multiple passkey credentials per user
- Credentials are tied to specific users and domains
- Sign count prevents replay attacks
- Backup eligible/state tracking for cross-device sync
- Resident key support for passwordless authentication

### Rate Limiting
- All endpoints are protected by Django REST Framework rate limiting
- Failed authentication attempts are throttled
- **Backup codes have strict rate limiting: 10 attempts per minute per IP address**
- Failed backup code attempts are logged for security monitoring

## Database Schema

### UserTwoFactorAuth
- `user`: OneToOneField to User
- `is_enabled`: Boolean flag for 2FA status
- `totp_secret`: CharField for TOTP secret
- `totp_enabled`: Boolean flag for TOTP status
- `passkey_enabled`: Boolean flag for passkey status
- `backup_codes`: JSONField for backup codes
- `created_at`/`updated_at`: Timestamps

### PasskeyCredential
- `user`: ForeignKey to User
- `credential_id`: Unique credential identifier
- `public_key`: TextField for public key
- `sign_count`: BigInteger for replay protection
- `transports`: JSONField for supported transports
- `rp_id`: CharField for relying party ID
- `user_handle`: CharField for user handle
- `created_at`/`last_used`: Timestamps

### LoginSession
- `user`: ForeignKey to User
- `session_id`: Unique session identifier
- `is_authenticated`: Boolean for completion status
- `requires_2fa`: Boolean for 2FA requirement
- `totp_verified`/`passkey_verified`: Boolean flags
- `created_at`/`expires_at`: Timestamps
- `ip_address`/`user_agent`: Client information

### FailedBackupCodeAttempt
- `user`: ForeignKey to User
- `ip_address`: GenericIPAddressField for tracking
- `user_agent`: TextField for browser/client info
- `attempted_code`: CharField for partial code (for monitoring)
- `created_at`: Timestamp of failed attempt

## Configuration

### Environment Variables
The following environment variables can be configured in your Django settings:

```python
# Database Configuration
LOCAL_DB=True  # Use SQLite for local development
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=your_db_host
DB_PORT=your_db_port

# Security Settings
SECRET_KEY=your_secret_key
DEBUG=True  # Set to False in production
ALLOWED_HOSTS=*  # Configure for production

# CSRF Settings
DJANGO_CSRF_TRUSTED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
DJANGO_CSRF_COOKIE_DOMAIN=yourdomain.com

# WebAuthn Configuration
WEBAUTHN_RP_ID=localhost  # Your domain
WEBAUTHN_RP_NAME=Lokdown Local  # Your application name
WEBAUTHN_ORIGIN=http://localhost:8000  # Your origin

# 2FA Configuration
BACKUP_CODE_RATE_LIMIT=10  # Rate limiting for backup codes (attempts per minute)
TWOFA_SESSION_TIMEOUT=10  # Session timeout for 2FA verification (minutes)
BACKUP_CODES_COUNT=8  # Number of backup codes to generate
BACKUP_CODE_LENGTH=10  # Backup code length (characters)
ADMIN_2FA_REQUIRED=True  # Require 2FA for admin users
```

### Django Settings Configuration

The application includes several non-default Django settings:

#### **Security Settings**
```python
# SSL/HTTPS Settings (disabled by default for development)
SECURE_SSL_REDIRECT = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 60
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 1209600  # 2 weeks in seconds
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'
```

#### **REST Framework Configuration**
```python
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.IsAuthenticated',),
    'DEFAULT_FORMAT_SUFFIXES': ['json'],  # Only allow JSON format
    'DEFAULT_VERSIONING_CLASS': None,  # Disable versioning
    'URL_FORMAT_OVERRIDE': None,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
    },
    'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework_simplejwt.authentication.JWTAuthentication'],
}
```

#### **JWT Configuration**
```python
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=5),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}
```

#### **API Documentation (Spectacular)**
```python
SPECTACULAR_SETTINGS = {
    'TITLE': 'Django Lokdown',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'CAMELIZE_NAMES': False,
    'SORT_OPERATIONS': False,
    'SORT_TAGS': True,
    'DISABLE_ERRORS_AND_WARNINGS': True,
    'CONTACT': {
        'name': 'Loknus Labs LLC',
        'email': 'loknuslabs@gmail.com',
        'url': 'https://loknuslabs.io',
    },
    'LICENSE': {
        'name': 'GNU General Public License v3.0',
        'url': 'https://www.gnu.org/licenses/gpl-3.0.html',
    },
}
```

### Dependencies

The following packages are required (see `requirements.txt`):

#### **Core Dependencies**
- `Django>=4.2.3`
- `djangorestframework`
- `djangorestframework-simplejwt`
- `django-cors-headers`
- `drf-spectacular`

#### **2FA Dependencies**
- `pyotp` - For TOTP generation and verification
- `webauthn` - For WebAuthn passkey support
- `qrcode` - For QR code generation
- `Pillow` - For image processing

#### **Database Dependencies**
- `mysqlclient` - For MySQL database support (optional)
- `sqlite3` - Built-in SQLite support

#### **Development Dependencies**
- `pytest-django` - For testing
- `black` - For code formatting
- `flake8` - For linting

## Installation

### Installing in Your Django Project

1. **Add to requirements.txt:**
```txt
# requirements.txt
Django>=4.2.3
djangorestframework
djangorestframework-simplejwt
django-cors-headers
drf-spectacular
django-lokdown  # Add this line
pyotp
webauthn
qrcode
Pillow
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Add to INSTALLED_APPS in your Django settings:**
```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'lokdown',  # Add this line
    # ... your other apps
]
```

4. **Include the URLs in your main urls.py:**
```python
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('lokdown.urls')),  # Add this line
    # ... your other URL patterns
]
```

5. **Configure environment variables in your Django settings:**
```python
# WebAuthn Configuration
WEBAUTHN_RP_ID = 'yourdomain.com'  # Your domain
WEBAUTHN_RP_NAME = 'Your App Name'  # Your application name
WEBAUTHN_ORIGIN = 'https://yourdomain.com'  # Your origin

# 2FA Configuration
BACKUP_CODE_RATE_LIMIT = 10  # Rate limiting for backup codes
TWOFA_SESSION_TIMEOUT = 10  # Session timeout for 2FA verification (minutes)
BACKUP_CODES_COUNT = 8  # Number of backup codes to generate
BACKUP_CODE_LENGTH = 10  # Backup code length (characters)
ADMIN_2FA_REQUIRED = True  # Require 2FA for admin users
```

6. **Run migrations:**
```bash
python manage.py migrate
```

7. **Optional: Customize admin interface (recommended):**
```python
# In your Django settings
ADMIN_SITE_HEADER = "Your App Admin"
ADMIN_SITE_TITLE = "Your App Administration"
ADMIN_INDEX_TITLE = "Welcome to Your App Administration"
```

### Development Installation

If you want to contribute to the library:

1. **Clone the repository:**
```bash
git clone https://github.com/your-username/django-lokdown.git
cd django-lokdown
```

2. **Install in development mode:**
```bash
pip install -e .
```

3. **Install development dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables:**
```bash
export WEBAUTHN_RP_ID="localhost"
export WEBAUTHN_RP_NAME="Django Lokdown"
export LOCAL_DB="True"
```

5. **Run migrations:**
```bash
python manage.py migrate
```

6**Run the development server:**
```bash
python manage.py runserver
```

**Note:** This development setup is only needed if you want to contribute to the library. For regular usage, just follow the "Installing in Your Django Project" steps above.

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For support, email loknuslabs@gmail.com or visit https://loknuslabs.io.