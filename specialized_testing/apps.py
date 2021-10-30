from django.apps import AppConfig


class SpecializedTestingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'specialized_testing'
