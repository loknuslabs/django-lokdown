from django.apps import AppConfig


class SecurityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'lokdown'
    verbose_name = 'Lokdown-Authentication'

    def ready(self):
        """Initialize the lokdown app when Django starts"""
        # Import signals if needed
        # from . import signals
        pass
