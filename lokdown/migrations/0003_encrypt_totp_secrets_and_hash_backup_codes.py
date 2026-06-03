from django.contrib.auth.hashers import make_password
from django.db import migrations, models


def encrypt_totp_secrets(apps, schema_editor):
    UserTimeBasedOneTimePasswords = apps.get_model("lokdown", "UserTimeBasedOneTimePasswords")
    from lokdown.helpers.encryption_helper import encrypt_secret, is_encrypted_value

    for row in UserTimeBasedOneTimePasswords.objects.all().iterator():
        changed = False
        if row.totp_secret and not is_encrypted_value(row.totp_secret):
            row.totp_secret = encrypt_secret(row.totp_secret)
            changed = True
        if row.pending_totp_secret and not is_encrypted_value(row.pending_totp_secret):
            row.pending_totp_secret = encrypt_secret(row.pending_totp_secret)
            changed = True
        if changed:
            row.save(update_fields=["totp_secret", "pending_totp_secret"])


def hash_backup_codes(apps, schema_editor):
    BackupCodes = apps.get_model("lokdown", "BackupCodes")
    from lokdown.helpers.backup_codes_helper import is_hashed_backup_code

    for row in BackupCodes.objects.all().iterator():
        codes = row.codes or []
        if not codes:
            continue
        if is_hashed_backup_code(codes[0]):
            continue
        row.codes = [make_password(code.upper()) for code in codes]
        row.save(update_fields=["codes"])


class Migration(migrations.Migration):

    dependencies = [
        ("lokdown", "0002_usertimebasedonetimepasswords_pending_totp_secret"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usertimebasedonetimepasswords",
            name="pending_totp_secret",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="usertimebasedonetimepasswords",
            name="totp_secret",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.RunPython(encrypt_totp_secrets, migrations.RunPython.noop),
        migrations.RunPython(hash_backup_codes, migrations.RunPython.noop),
    ]
