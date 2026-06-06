from datetime import timedelta

from django.contrib import admin
from django.db.models import Q
from django.contrib.admin import SimpleListFilter
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.safestring import mark_safe

from lokdown.helpers.auth_flow_helper import disable_user_2fa
from lokdown.helpers.backup_codes_helper import generate_backup_codes, store_backup_codes
from lokdown.helpers.passkey_helper import has_passkey_enabled
from lokdown.helpers.totp_helper import has_totp_enabled
from lokdown.models import (
    BackupCodes,
    FailedBackupCodeAttempt,
    LoginSession,
    PasskeyCredential,
    UserApiKey,
    UserTimeBasedOneTimePasswords,
)


class RecentActivityFilter(SimpleListFilter):
    title = "Recent Activity"
    parameter_name = "recent_activity"

    def lookups(self, request, model_admin):
        return (
            ("1h", "Last Hour"),
            ("24h", "Last 24 Hours"),
            ("7d", "Last 7 Days"),
            ("30d", "Last 30 Days"),
        )

    def queryset(self, request, queryset):
        if self.value():
            hours = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}
            cutoff = timezone.now() - timedelta(hours=hours[self.value()])
            return queryset.filter(created_at__gte=cutoff)
        return queryset


class TotpStatusFilter(SimpleListFilter):
    title = "TOTP status"
    parameter_name = "totp_status"

    def lookups(self, request, model_admin):
        return (("enabled", "TOTP enabled"), ("disabled", "TOTP disabled"))

    def queryset(self, request, queryset):
        if self.value() == "enabled":
            return queryset.exclude(totp_secret__isnull=True).exclude(totp_secret="")
        if self.value() == "disabled":
            return queryset.filter(Q(totp_secret__isnull=True) | Q(totp_secret=""))
        return queryset


@admin.register(UserTimeBasedOneTimePasswords)
class UserTimeBasedOneTimePasswordsAdmin(admin.ModelAdmin):
    list_display = ("user", "totp_status", "created_at", "updated_at", "last_used")
    list_filter = (TotpStatusFilter, "created_at", "updated_at")
    search_fields = ("user__username", "user__email", "user__first_name", "user__last_name")
    readonly_fields = ("created_at", "updated_at", "last_used")
    actions = ["disable_2fa_for_users", "regenerate_backup_codes"]

    fieldsets = (
        ("User", {"fields": ("user",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at", "last_used"), "classes": ("collapse",)}),
    )

    @admin.display(boolean=True, description="TOTP enabled")
    def totp_status(self, obj):
        return bool(obj.totp_secret)

    @admin.action(description="Disable all 2FA for selected users")
    def disable_2fa_for_users(self, request, queryset):
        count = 0
        for row in queryset.select_related("user"):
            disable_user_2fa(row.user)
            count += 1
        self.message_user(request, f"2FA disabled for {count} user(s).")

    @admin.action(description="Regenerate backup codes (requires TOTP or passkey)")
    def regenerate_backup_codes(self, request, queryset):
        updated = 0
        for row in queryset.select_related("user"):
            if has_totp_enabled(row.user) or has_passkey_enabled(row.user):
                store_backup_codes(row.user, generate_backup_codes())
                updated += 1
        self.message_user(
            request,
            f"Regenerated backup codes for {updated} user(s). "
            "New codes are stored securely and cannot be displayed from admin.",
        )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")

    def add_view(self, request, form_url="", extra_context=None):
        return redirect("admin_current_user_totp_setup")

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(PasskeyCredential)
class PasskeyCredentialAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "credential_id_short",
        "sign_count",
        "created_at",
        "last_used",
        "days_since_use",
    )
    list_filter = ("created_at", "last_used")
    search_fields = ("user__username", "user__email", "credential_id")
    readonly_fields = (
        "credential_id",
        "public_key",
        "sign_count",
        "rp_id",
        "user_handle",
        "transports",
        "created_at",
        "last_used",
    )

    fieldsets = (
        ("User", {"fields": ("user",)}),
        ("Credential", {"fields": ("credential_id", "public_key", "sign_count", "transports")}),
        ("WebAuthn", {"fields": ("rp_id", "user_handle")}),
        ("Timestamps", {"fields": ("created_at", "last_used"), "classes": ("collapse",)}),
    )

    @admin.display(description="Credential ID")
    def credential_id_short(self, obj):
        cid = obj.credential_id
        return cid[:20] + "..." if len(cid) > 20 else cid

    @admin.display(description="Last used")
    def days_since_use(self, obj):
        if not obj.last_used:
            return "Never used"
        days = (timezone.now() - obj.last_used).days
        if days == 0:
            return "Today"
        if days == 1:
            return "Yesterday"
        return f"{days} days ago"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")

    def add_view(self, request, form_url="", extra_context=None):
        return redirect("admin_current_user_passkey_setup")

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(BackupCodes)
class BackupCodesAdmin(admin.ModelAdmin):
    list_display = ("user", "remaining_count", "created_at", "updated_at")
    list_filter = ("created_at", "updated_at")
    search_fields = ("user__username", "user__email")
    readonly_fields = ("created_at", "updated_at")
    actions = ["regenerate_codes"]

    @admin.display(description="Remaining codes")
    def remaining_count(self, obj):
        return len(obj.codes or [])

    @admin.action(description="Regenerate backup codes")
    def regenerate_codes(self, request, queryset):
        updated = 0
        for obj in queryset.select_related("user"):
            if has_totp_enabled(obj.user) or has_passkey_enabled(obj.user):
                store_backup_codes(obj.user, generate_backup_codes())
                updated += 1
        self.message_user(
            request,
            f"Regenerated codes for {updated} user(s). "
            "New codes are stored securely and cannot be displayed from admin.",
        )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(LoginSession)
class LoginSessionAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "session_id_short",
        "security_status",
        "ip_address",
        "created_at",
        "expires_at",
        "is_expired",
    )
    list_filter = (
        RecentActivityFilter,
        "is_authenticated",
        "requires_2fa",
        "totp_verified",
        "passkey_verified",
        "created_at",
    )
    search_fields = ("user__username", "user__email", "session_id", "ip_address")
    readonly_fields = (
        "session_id",
        "user",
        "is_authenticated",
        "requires_2fa",
        "totp_verified",
        "passkey_verified",
        "challenge",
        "ip_address",
        "user_agent",
        "created_at",
        "expires_at",
    )
    actions = ["expire_sessions", "delete_expired_sessions"]

    @admin.display(description="Session ID")
    def session_id_short(self, obj):
        sid = obj.session_id
        return sid[:20] + "..." if len(sid) > 20 else sid

    @admin.display(description="Status")
    def security_status(self, obj):
        if obj.is_authenticated:
            return mark_safe('<span style="color:#48bb78;">Authenticated</span>')
        if obj.totp_verified:
            return mark_safe('<span style="color:#ed8936;">TOTP verified</span>')
        if obj.passkey_verified:
            return mark_safe('<span style="color:#ed8936;">Passkey verified</span>')
        if obj.requires_2fa:
            return mark_safe('<span style="color:#e53e3e;">Pending 2FA</span>')
        return mark_safe('<span style="color:#a0aec0;">Open</span>')

    @admin.display(boolean=True, description="Expired")
    def is_expired(self, obj):
        return obj.expires_at < timezone.now()

    @admin.action(description="Expire selected sessions")
    def expire_sessions(self, request, queryset):
        updated = queryset.update(expires_at=timezone.now())
        self.message_user(request, f"Expired {updated} session(s).")

    @admin.action(description="Delete expired sessions")
    def delete_expired_sessions(self, request, queryset):
        expired = queryset.filter(expires_at__lt=timezone.now())
        count = expired.count()
        expired.delete()
        self.message_user(request, f"Deleted {count} expired session(s).")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(FailedBackupCodeAttempt)
class FailedBackupCodeAttemptAdmin(admin.ModelAdmin):
    list_display = ("user", "ip_address", "attempted_code", "user_agent_short", "created_at", "time_ago")
    list_filter = (RecentActivityFilter, "ip_address", "created_at")
    search_fields = ("user__username", "user__email", "ip_address", "attempted_code")
    readonly_fields = ("user", "ip_address", "user_agent", "attempted_code", "created_at")

    @admin.display(description="User agent")
    def user_agent_short(self, obj):
        if not obj.user_agent:
            return "N/A"
        return obj.user_agent[:30] + "..." if len(obj.user_agent) > 30 else obj.user_agent

    @admin.display(description="When")
    def time_ago(self, obj):
        diff = timezone.now() - obj.created_at
        if diff.days > 0:
            return f"{diff.days} days ago"
        if diff.seconds > 3600:
            return f"{diff.seconds // 3600} hours ago"
        if diff.seconds > 60:
            return f"{diff.seconds // 60} minutes ago"
        return "Just now"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin.register(UserApiKey)
class UserApiKeyAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "name",
        "prefix",
        "is_active_display",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    )
    list_filter = ("created_at", "last_used_at", "expires_at", "revoked_at")
    search_fields = ("user__username", "user__email", "name", "prefix")
    readonly_fields = (
        "user",
        "name",
        "prefix",
        "key_hash",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    )
    actions = ["revoke_selected_keys"]

    @admin.display(boolean=True, description="Active")
    def is_active_display(self, obj):
        if obj.revoked_at is not None:
            return False
        if obj.expires_at is not None and obj.expires_at < timezone.now():
            return False
        return True

    @admin.action(description="Revoke selected API keys")
    def revoke_selected_keys(self, request, queryset):
        updated = queryset.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
        self.message_user(request, f"Revoked {updated} API key(s).")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
