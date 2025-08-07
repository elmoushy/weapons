from django.apps import AppConfig


class NewsServiceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'news_service'
    verbose_name = 'News Service'
    
    def ready(self):
        """
        Initialize the news service when Django starts
        """
        # Import signal handlers if any
        # from . import signals
        pass
