# Dokploy deployment

Production is built from `NC3-LU/TestingPlatform`, branch `main`, using
`deploy/compose.yml` on `testingplatformprodvm2`. Configure the existing NC3 GitHub
provider in Dokploy and enable automatic deployment for pushes to `main`.

Set a private `SECRET_KEY` in Dokploy. Keep it stable across deployments.
Set `TESTING_DATA_ROOT` in Dokploy to an existing absolute host directory containing
`db/db.sqlite3` and `files/`. These directories must be readable and writable by
UID/GID 33 (`www-data`). Keep this directory outside the Git checkout. Bind mounts
refuse missing host paths, startup refuses a missing database, and SQLite opens in
`mode=rw` so a missing database cannot be silently recreated.

**Never delete the original database, database copies, uploads, or backups.**
The migration uses a separate, verified SQLite backup and a separate uploads copy.
Application rebuilds and container replacements reuse the same persistent paths.
Do not use `down -v`, volume pruning, database resets, or flush commands.
Database migrations are intentionally not run on startup. Schema changes need a
reviewed migration and a verified backup before the corresponding code is deployed.

Apache continues to terminate HTTPS and renew the existing certificate, proxying
to `127.0.0.1:18080`. The nginx container serves static assets built from the same
source and proxies Django to `127.0.0.1:18081`. Neither container listens on a public
address. Host networking preserves IPv6 testing and the loopback-only SMTP relay.
The former mod_wsgi application must be disabled at cutover; retaining Apache as
the HTTPS proxy does not keep the legacy application running.

The original service had no active Django Q worker. This deployment preserves that
state; enabling a worker requires reviewing the existing scheduled tasks first.

Validate changes with:

```sh
python -m unittest discover -s deploy/tests -v
docker compose -f deploy/compose.yml config --quiet
```

Before cutover, test on a separate database/uploads copy, check database integrity
and table counts, exercise non-mutating application routes, and compare uploads.
After stopping legacy writes, create a fresh final backup and production copy.
Keep the original database and source for recovery. If the new application has
accepted writes, recovery must preserve those newer writes before switching back.
