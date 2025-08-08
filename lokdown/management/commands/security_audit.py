from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from django.db import models
from lokdown.models import (
    UserTimeBasedOneTimePasswords,
    PasskeyCredential,
    LoginSession,
    FailedBackupCodeAttempt,
)


class Command(BaseCommand):
    help = 'Perform lokdown audit and generate reports'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=30, help='Number of days to look back for recent activity')
        parser.add_argument('--export', action='store_true', help='Export detailed lokdown report')
        parser.add_argument('--cleanup', action='store_true', help='Clean up old lokdown data')

    def handle(self, *args, **options):
        days = options['days']
        export = options['export']
        cleanup = options['cleanup']

        self.stdout.write(self.style.SUCCESS('🔒 Security Audit Report'))
        self.stdout.write('=' * 50)

        # Calculate lokdown statistics
        total_users = UserTimeBasedOneTimePasswords.objects.count()

        # Count users with 2FA enabled (either TOTP or Passkey)
        enabled_2fa = (
            UserTimeBasedOneTimePasswords.objects.filter(
                models.Q(totp_secret__isnull=False) | models.Q(user__passkey_credentials__isnull=False)
            )
            .distinct()
            .count()
        )

        # Count users with TOTP
        totp_users = UserTimeBasedOneTimePasswords.objects.filter(totp_secret__isnull=False).count()

        # Count users with Passkey
        passkey_users = PasskeyCredential.objects.values('user').distinct().count()

        # Recent activity
        cutoff_date = timezone.now() - timedelta(days=days)
        recent_sessions = LoginSession.objects.filter(created_at__gte=cutoff_date).count()
        recent_failed_attempts = FailedBackupCodeAttempt.objects.filter(created_at__gte=cutoff_date).count()

        # Security alerts
        users_without_backup_codes = (
            UserTimeBasedOneTimePasswords.objects.filter(
                models.Q(totp_secret__isnull=False) | models.Q(user__passkey_credentials__isnull=False)
            )
            .filter(user__backup_codes__codes__len=0)
            .distinct()
            .count()
        )

        old_passkeys = PasskeyCredential.objects.filter(last_used__lt=timezone.now() - timedelta(days=90)).count()

        # Calculate lokdown score
        if total_users > 0:
            adoption_rate = (enabled_2fa / total_users) * 100
            threat_level = min(recent_failed_attempts * 5, 50)
            security_score = max(0, adoption_rate - threat_level)
        else:
            security_score = 0

        # Print statistics
        self.stdout.write(f'\n📊 Security Statistics:')
        self.stdout.write(f'  Total users with 2FA settings: {total_users}')
        self.stdout.write(
            f'  2FA enabled: {enabled_2fa} ({enabled_2fa / total_users * 100:.1f}% adoption)'
            if total_users > 0
            else '  2FA enabled: 0 (0% adoption)'
        )
        self.stdout.write(f'  TOTP users: {totp_users}')
        self.stdout.write(f'  Passkey users: {passkey_users}')
        self.stdout.write(f'  Security Score: {security_score:.1f}/100')

        self.stdout.write(f'\n📈 Recent Activity (Last {days} days):')
        self.stdout.write(f'  Login sessions: {recent_sessions}')
        self.stdout.write(f'  Failed backup attempts: {recent_failed_attempts}')

        self.stdout.write(f'\n⚠️  Security Alerts:')
        if users_without_backup_codes > 0:
            self.stdout.write(self.style.WARNING(f'  Users without backup codes: {users_without_backup_codes}'))
        else:
            self.stdout.write(self.style.SUCCESS('  All 2FA users have backup codes'))

        if old_passkeys > 0:
            self.stdout.write(self.style.WARNING(f'  Old passkeys (90+ days): {old_passkeys}'))
        else:
            self.stdout.write(self.style.SUCCESS('  No old passkeys found'))

        if recent_failed_attempts > 10:
            self.stdout.write(self.style.ERROR(f'  High number of failed attempts: {recent_failed_attempts}'))
        else:
            self.stdout.write(self.style.SUCCESS('  Failed attempts within normal range'))

        # Export functionality
        if export:
            self.export_security_report()

        # Cleanup functionality
        if cleanup:
            self.cleanup_old_data()

        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS('Security audit completed!'))

    def export_security_report(self):
        """Export detailed lokdown report"""
        self.stdout.write('\n📄 Exporting lokdown report...')
        # This would generate a CSV or JSON report
        self.stdout.write('  Report export functionality would be implemented here')

    def cleanup_old_data(self):
        """Clean up old lokdown data"""
        self.stdout.write('\n🧹 Cleaning up old data...')

        # Clean up expired sessions
        expired_sessions = LoginSession.objects.filter(expires_at__lt=timezone.now())
        expired_count = expired_sessions.count()
        expired_sessions.delete()
        self.stdout.write(f'  Deleted {expired_count} expired sessions')

        # Clean up old failed attempts (older than 30 days)
        old_attempts = FailedBackupCodeAttempt.objects.filter(created_at__lt=timezone.now() - timedelta(days=30))
        attempts_count = old_attempts.count()
        old_attempts.delete()
        self.stdout.write(f'  Deleted {attempts_count} old failed attempts')

        # Clean up old passkeys (older than 90 days)
        old_passkeys = PasskeyCredential.objects.filter(last_used__lt=timezone.now() - timedelta(days=90))
        passkeys_count = old_passkeys.count()
        old_passkeys.delete()
        self.stdout.write(f'  Deleted {passkeys_count} old passkeys')
