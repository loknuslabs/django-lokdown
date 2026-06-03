from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lokdown", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="usertimebasedonetimepasswords",
            name="pending_totp_secret",
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
    ]
