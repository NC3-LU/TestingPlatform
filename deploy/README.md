# Dokploy deployment

This Compose configuration builds application and static-asset images for
Dokploy. Select your repository and deployment branch, and use
`deploy/compose.yml` as the Compose file.

Set a private `SECRET_KEY` in Dokploy. Keep it stable across deployments.
Set `TESTING_DATA_ROOT` in Dokploy to an existing absolute host directory containing
`db/db.sqlite3` and `files/`. These directories must be readable and writable by
UID/GID 33 (`www-data`). Keep this directory outside the Git checkout. Bind mounts
refuse missing host paths, startup refuses a missing database, and SQLite opens in
`mode=rw` so a missing database cannot be silently recreated.

Prepare a database and uploads directory before starting the services.
Verify backups before making database or storage changes.
Application rebuilds and container replacements reuse the same persistent paths.
Do not use `down -v`, volume pruning, database resets, or flush commands.
Database migrations are intentionally not run on startup. Schema changes need a
reviewed migration and a verified backup before the corresponding code is deployed.

Configure an HTTPS reverse proxy to forward requests to the nginx service
on `127.0.0.1:18080`. The nginx service serves static assets and forwards
application requests to Gunicorn on `127.0.0.1:18081`. Host networking
supports IPv6 network tests.


Validate changes with:

```sh
python -m unittest discover -s deploy/tests -v
docker compose -f deploy/compose.yml config --quiet
```

Validate database integrity, uploaded files, static assets, and HTTPS behavior
in a test environment before deploying. Keep installation-specific migration
and recovery procedures in private operator documentation.
