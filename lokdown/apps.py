from django.apps import AppConfig


class LokdownConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "lokdown"
    verbose_name = "Lokdown Authentication"

    def ready(self):
        from lokdown import checks  # noqa: F401
        from lokdown import spectacular_extensions  # noqa: F401
