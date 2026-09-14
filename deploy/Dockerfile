FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS frontend
WORKDIR /frontend
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund \
    && test -s node_modules/bootstrap/dist/css/bootstrap.min.css \
    && test -s node_modules/bootstrap/dist/js/bootstrap.bundle.min.js

FROM python:3.13-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DEBUG=0 \
    ALLOWED_HOSTS=testing.nc3.lu PKGVER=GitHub-0-gmain
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libxml2-dev libxslt1-dev \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    shared-mime-info fonts-dejavu-core iputils-ping nmap bind9-dnsutils whois \
    openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt deploy/gunicorn-requirement.txt /tmp/
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && pip install --no-cache-dir --require-hashes --no-deps -r /tmp/gunicorn-requirement.txt
COPY . /app/
COPY deploy/start.sh /app/start.sh
RUN chmod 755 /app/start.sh \
    && mkdir -p /app/db /app/files \
    && mkdir -p /run/testingplatform && chown www-data:www-data /run/testingplatform \
    && DEBUG=1 python manage.py collectstatic --noinput \
    && test ! -e /app/db/db.sqlite3
ENV DJANGO_SETTINGS_MODULE=deploy.settings
USER www-data
ENTRYPOINT ["/app/start.sh"]

FROM nginx:stable-alpine@sha256:dc5069ad14f19660b141b21236140b91656bf89bbc3e2417c70ae650cd66104c AS proxy
COPY --from=app /app/static/ /srv/testing-static/
COPY --from=frontend /frontend/node_modules/ /srv/testing-static/npm_components/
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
