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

Traefik terminates HTTPS and manages certificate renewal.
In the Compose service's Dokploy Domains settings, route `testing.nc3.lu`, path
`/`, to service `proxy`, port `80`, with HTTPS and the `letsencrypt` resolver.
The nginx container joins `dokploy-network`, serves the built static assets and
forwards Django requests over the private `runtime` volume's Unix socket.
Its loopback-only `127.0.0.1:18080` mapping supports local health checks.

The Django container uses host networking for IPv6 network tests.
Gunicorn listens on a Unix socket. Only the web and nginx containers
mount the socket volume. Traefik sets `X-Forwarded-Proto`, nginx preserves it,
and the deployment settings recognize public HTTPS for generated links and CSRF.

Mail settings (`EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USE_TLS`, `EMAIL_HOST_USER`,
`EMAIL_HOST_PASSWORD`, `DEFAULT_FROM_EMAIL`) are supplied privately in Dokploy.

Validate changes with:

```sh
DJANGO_SETTINGS_MODULE=deploy.settings python -m unittest discover -s deploy/tests -v
docker compose -f deploy/compose.yml config --quiet
```

Validate database integrity, uploaded files, static assets, and HTTPS behavior
in a test environment before deploying. Keep installation-specific migration
and recovery procedures in private operator documentation.
