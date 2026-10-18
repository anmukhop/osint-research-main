from django.apps import AppConfig
import os


class ResearcherConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'researcher'

    def ready(self):
        # Skip warmup for management commands like migrate, makemigrations,
        # collectstatic, shell, etc. Only warm when actually serving requests.
        if os.environ.get("RUN_MAIN") != "true" and "runserver" not in os.sys.argv:
            # Running under gunicorn or similar — warm immediately.
            pass
        elif "runserver" in os.sys.argv and os.environ.get("RUN_MAIN") != "true":
            # runserver's parent reloader process — skip, child will do it
            return

        try:
            from .services.mcp_runtime import get_runtime
            runtime = get_runtime()
            # Fire-and-forget: start() is non-blocking, the background thread
            # will finish connecting over the next ~10-20 seconds. We don't
            # block Django startup on it.
            runtime.start()
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Failed to warm MCP runtime")