from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.dispatch import receiver


class TesterConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tester'

    def ready(self):
        post_migrate.connect(create_superuser, sender=self)


@receiver(post_migrate)
def create_superuser(sender, **kwargs):
    from django.contrib.auth.models import User

    username = 'admin'
    password = 'password'
    email = 'admin@example.com'

    if not User.objects.filter(is_superuser=True).exists():
        User.objects.create_superuser(username=username, email=email, password=password)
        print(f'Default superuser ({username}) with password ({password}) created')