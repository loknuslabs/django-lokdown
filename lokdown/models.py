from django.db import models
from django.contrib.auth.models import User


class UserTimeBasedOneTimePasswords(models.Model):
    """Model to store TOTP settings for users"""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='two_factor_auth')
    totp_secret = models.CharField(max_length=32, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"TOTP settings for {self.user.username}"

    class Meta:
        verbose_name = "User TOTP Authentication"
        verbose_name_plural = "User TOTP Authentications"


class PasskeyCredential(models.Model):
    """Model to store WebAuthn passkey credentials"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='passkey_credentials')
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    rp_id = models.CharField(max_length=255)
    user_handle = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Passkey for {self.user.username} - {self.credential_id[:20]}..."

    class Meta:
        verbose_name = "User Passkey Credential"
        verbose_name_plural = "User Passkey Credentials"


class BackupCodes(models.Model):
    """Model to store backup codes for 2FA users (TOTP or Passkey)"""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='backup_codes')
    codes = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Backup codes for {self.user.username}"

    class Meta:
        verbose_name = "User Backup Codes"
        verbose_name_plural = "User Backup Codes"


class LoginSession(models.Model):
    """Model to track login sessions for 2FA flow"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_sessions')
    session_id = models.CharField(max_length=64, unique=True)
    is_authenticated = models.BooleanField(default=False)
    requires_2fa = models.BooleanField(default=False)
    totp_verified = models.BooleanField(default=False)
    passkey_verified = models.BooleanField(default=False)
    challenge = models.TextField(null=True, blank=True)  # Store WebAuthn challenge
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    def __str__(self):
        return f"Login session for {self.user.username} - {self.session_id[:20]}..."

    class Meta:
        verbose_name = "Login Session"
        verbose_name_plural = "Login Sessions"


class FailedBackupCodeAttempt(models.Model):
    """Model to track failed backup code attempts for lokdown monitoring"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='failed_backup_attempts')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    attempted_code = models.CharField(max_length=10, blank=True)  # Store partial for monitoring
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Failed backup attempt for {self.user.username} from {self.ip_address} at {self.created_at}"

    class Meta:
        verbose_name = "Failed Backup Code Attempt"
        verbose_name_plural = "Failed Backup Code Attempts"
        ordering = ['-created_at']
