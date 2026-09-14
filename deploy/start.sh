#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -s db/db.sqlite3 ]; then
    echo 'Refusing to start without the existing database copy at db/db.sqlite3' >&2
    exit 78
fi
exec python -m gunicorn testing_platform.wsgi:application \
    --bind unix:/run/testingplatform/gunicorn.sock --umask 0111 \
    --workers 1 --worker-class gthread --threads 2 \
    --timeout 330 --graceful-timeout 330 --access-logfile - --error-logfile -
