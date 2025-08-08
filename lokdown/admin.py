from datetime import timedelta
from django.contrib import admin
from django.contrib.admin import SimpleListFilter
from django.utils import timezone
from .helpers.backup_codes_helper import generate_backup_codes
from .models import *
from django.utils.safestring import mark_safe
from django.shortcuts import redirect


# Custom filters for security monitoring
class RecentActivityFilter(SimpleListFilter):
    title = 'Recent Activity'
    parameter_name = 'recent_activity'

    def lookups(self, request, model_admin):
        return (
            ('1h', 'Last Hour'),
            ('24h', 'Last 24 Hours'),
            ('7d', 'Last 7 Days'),
            ('30d', 'Last 30 Days'),
        )

    def queryset(self, request, queryset):
        if self.value():
            hours = {
                '1h': 1,
                '24h': 24,
                '7d': 24 * 7,
                '30d': 24 * 30,
            }
            cutoff = timezone.now() - timedelta(hours=hours[self.value()])
            return queryset.filter(created_at__gte=cutoff)
        return queryset


class SecurityStatusFilter(SimpleListFilter):
    title = 'Security Status'
    parameter_name = 'security_status'

    def lookups(self, request, model_admin):
        return (
            ('enabled', 'TOTP Enabled'),
            ('disabled', 'TOTP Disabled'),
        )

    def queryset(self, request, queryset):
        if self.value() == 'enabled':
            return queryset.filter(is_enabled=True, totp_enabled=True)
        elif self.value() == 'disabled':
            return queryset.filter(is_enabled=False)
        return queryset


@admin.register(UserTimeBasedOneTimePasswords)
class UserTwoFactorAuthAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'created_at',
        'updated_at',
    )
    list_filter = (SecurityStatusFilter, 'created_at', 'updated_at')
    search_fields = ('user__username', 'user__email', 'user__first_name', 'user__last_name')
    readonly_fields = ('created_at', 'updated_at')
    actions = ['enable_totp', 'disable_totp', 'reset_backup_codes', 'export_security_report']

    fieldsets = (
        ('User Information', {'fields': ('user',)}),
        ('TOTP Configuration', {'fields': ('totp_secret',), 'classes': ('collapse',)}),
        ('Timestamps', {'fields': ('created_at', 'updated_at'), 'classes': ('collapse',)}),
    )

    def enable_totp(self, request, queryset):
        updated = queryset.update(is_enabled=True)
        self.message_user(request, f'{updated} users had TOTP enabled.')

    enable_totp.short_description = "Enable TOTP for selected users"

    def disable_totp(self, request, queryset):
        updated = queryset.update(
            is_enabled=False, totp_enabled=False, passkey_enabled=False, totp_secret=None, backup_codes=[]
        )
        self.message_user(request, f'{updated} users had TOTP disabled.')

    disable_totp.short_description = "Disable TOTP for selected users"

    def reset_backup_codes(self, request, queryset):
        updated = 0
        for obj in queryset:
            if obj.totp_enabled:
                obj.backup_codes = generate_backup_codes()
                obj.save()
                updated += 1
        self.message_user(request, f'{updated} users had backup codes regenerated.')

    reset_backup_codes.short_description = "Regenerate backup codes for selected users"

    def export_security_report(self, request):
        # This would generate a CSV report of security status
        self.message_user(request, 'Security report export feature would be implemented here.')

    export_security_report.short_description = "Export security report"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

    def add_view(self, request, form_url='', extra_context=None):
        return redirect('admin_current_user_totp_setup')

    def has_change_permission(self, request, obj=...):
        return False


@admin.register(PasskeyCredential)
class PasskeyCredentialAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'credential_id_short',
        'sign_count',
        'created_at',
        'last_used',
        'days_since_use',
    )
    list_filter = ('created_at', 'last_used')
    search_fields = ('user__username', 'user__email', 'credential_id')
    readonly_fields = ('created_at', 'last_used', 'credential_id_full', 'public_key_preview')
    actions = ['setup_passkey_for_current_user']

    fieldsets = (
        ('User Information', {'fields': ('user',)}),
        ('Credential Details', {'fields': ('sign_count',)}),
        ('Security Settings', {'fields': ('rp_id', 'user_handle')}),
        ('Timestamps', {'fields': ('created_at', 'last_used'), 'classes': ('collapse',)}),
    )

    def credential_id_short(self, obj):
        return obj.credential_id[:20] + '...' if len(obj.credential_id) > 20 else obj.credential_id

    credential_id_short.short_description = 'Credential ID'

    def credential_id_full(self, obj):
        return obj.credential_id

    credential_id_full.short_description = 'Full Credential ID'

    def public_key_preview(self, obj):
        return obj.public_key[:50] + '...' if len(obj.public_key) > 50 else obj.public_key

    public_key_preview.short_description = 'Public Key Preview'

    def days_since_use(self, obj):
        if obj.last_used:
            days = (timezone.now() - obj.last_used).days
            if days == 0:
                return 'Today'
            elif days == 1:
                return 'Yesterday'
            else:
                return f'{days} days ago'
        return 'Never used'

    days_since_use.short_description = 'Last Used'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

    def add_view(self, request, form_url='', extra_context=None):
        return redirect('admin_current_user_passkey_setup')

    def setup_passkey_for_current_user(self):
        return redirect('admin_current_user_passkey_setup')

    setup_passkey_for_current_user.short_description = "Setup passkey for current admin user"

    def has_change_permission(self, request, obj=...):
        return False


@admin.register(LoginSession)
class LoginSessionAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'session_id_short',
        'security_status',
        'ip_address',
        'created_at',
        'expires_at',
        'is_expired',
    )
    list_filter = (
        RecentActivityFilter,
        'is_authenticated',
        'totp_verified',
        'passkey_verified',
        'created_at',
    )
    search_fields = ('user__username', 'user__email', 'session_id', 'ip_address')
    readonly_fields = ('created_at', 'expires_at', 'session_id_full')
    actions = ['expire_sessions', 'delete_expired_sessions']

    fieldsets = (
        ('Session Information', {'fields': ('user', 'session_id_full', 'is_authenticated')}),
        ('Verification Status', {'fields': ('totp_verified', 'passkey_verified')}),
        ('Client Information', {'fields': ('ip_address', 'user_agent')}),
        ('Timestamps', {'fields': ('created_at', 'expires_at'), 'classes': ('collapse',)}),
    )

    def session_id_short(self, obj):
        return obj.session_id[:20] + '...' if len(obj.session_id) > 20 else obj.session_id

    session_id_short.short_description = 'Session ID'

    def session_id_full(self, obj):
        return obj.session_id

    session_id_full.short_description = 'Full Session ID'

    def security_status(self, obj):
        if obj.is_authenticated:
            return mark_safe('<span style="color: #48bb78; font-weight: 500;">✅ Authenticated</span>')
        elif obj.requires_2fa:
            if obj.totp_verified or obj.passkey_verified:
                return mark_safe('<span style="color: #ed8936; font-weight: 500;">🟠 TOTP Verified</span>')
            else:
                return mark_safe('<span style="color: #e53e3e; font-weight: 500;">🔴 TOTP Pending</span>')
        else:
            return mark_safe('<span style="color: #a0aec0; font-weight: 500;">⚪ No TOTP</span>')

    security_status.short_description = 'Security Status'

    def is_expired(self, obj):
        if obj.expires_at < timezone.now():
            return mark_safe('<span style="color: #e53e3e; font-weight: 500;">Expired</span>')
        else:
            return mark_safe('<span style="color: #48bb78; font-weight: 500;">Active</span>')

    is_expired.short_description = 'Status'

    def expire_sessions(self, request, queryset):
        updated = queryset.update(expires_at=timezone.now())
        self.message_user(request, f'{updated} sessions expired.')

    expire_sessions.short_description = "Expire selected sessions"

    def delete_expired_sessions(self, request, queryset):
        expired = queryset.filter(expires_at__lt=timezone.now())
        count = expired.count()
        expired.delete()
        self.message_user(request, f'{count} expired sessions deleted.')

    delete_expired_sessions.short_description = "Delete expired sessions"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

    def has_add_permission(self, request):
        return False  # Prevent manual creation of failed attempts

    def has_change_permission(self, request, obj=...):
        return False

    def has_delete_permission(self, request, obj=...):
        return False


@admin.register(FailedBackupCodeAttempt)
class FailedBackupCodeAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'ip_address', 'attempted_code', 'user_agent_short', 'created_at', 'time_ago')
    list_filter = (RecentActivityFilter, 'ip_address', 'created_at')
    search_fields = ('user__username', 'user__email', 'ip_address', 'attempted_code')
    readonly_fields = ('created_at', 'user_agent_full')
    actions = ['block_ip_addresses', 'export_security_log']

    fieldsets = (
        ('Attempt Information', {'fields': ('user', 'ip_address', 'attempted_code')}),
        ('Client Information', {'fields': ('user_agent_full',)}),
        ('Timestamps', {'fields': ('created_at',), 'classes': ('collapse',)}),
    )

    def user_agent_short(self, obj):
        if obj.user_agent:
            return obj.user_agent[:30] + '...' if len(obj.user_agent) > 30 else obj.user_agent
        return 'N/A'

    user_agent_short.short_description = 'User Agent'

    def user_agent_full(self, obj):
        return obj.user_agent or 'N/A'

    user_agent_full.short_description = 'Full User Agent'

    def time_ago(self, obj):
        now = timezone.now()
        diff = now - obj.created_at

        if diff.days > 0:
            return f'{diff.days} days ago'
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f'{hours} hours ago'
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f'{minutes} minutes ago'
        else:
            return 'Just now'

    time_ago.short_description = 'Time Ago'

    def block_ip_addresses(self, request, queryset):
        # This would integrate with your firewall/security system
        unique_ips = queryset.values_list('ip_address', flat=True).distinct()
        self.message_user(request, f'Would block {len(unique_ips)} IP addresses: {", ".join(unique_ips)}')

    block_ip_addresses.short_description = "Block IP addresses (integration needed)"

    def export_security_log(self, request):
        # This would generate a security log export
        self.message_user(request, 'Security log export feature would be implemented here.')

    export_security_log.short_description = "Export security log"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

    def has_add_permission(self, request):
        return False  # Prevent manual creation of failed attempts

    def has_change_permission(self, request, obj=...):
        return False

    def has_delete_permission(self, request, obj=...):
        return False
