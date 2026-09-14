"""Django settings for the Dokploy Compose deployment."""

from testing_platform.settings import *  # noqa: F403
from testing_platform.settings import BASE_DIR, DATABASES

# Traefik sets the scheme at the public edge; nginx preserves it on the private
# socket. The application has no public HTTP listener.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# SQLite must open an existing database, never silently create an empty one.
DATABASES = {
    "default": {
        **DATABASES["default"],
        "NAME": (BASE_DIR / "db" / "db.sqlite3").as_uri() + "?mode=rw",
        "OPTIONS": {"uri": True},
    }
}
