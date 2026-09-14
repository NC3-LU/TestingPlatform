"""Settings for the existing-database deployment managed by Dokploy."""

from testing_platform.settings import *  # noqa: F403
from testing_platform.settings import BASE_DIR, DATABASES

# SQLite must open an existing database, never silently create an empty one.
DATABASES = {
    "default": {
        **DATABASES["default"],
        "NAME": (BASE_DIR / "db" / "db.sqlite3").as_uri() + "?mode=rw",
        "OPTIONS": {"uri": True},
    }
}
