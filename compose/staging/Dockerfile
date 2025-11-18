FROM python:latest
ARG DEBUG
ENV PYTHONUNBUFFERED 1

ENV APP_ROOT /var/www/testing_platform
WORKDIR ${APP_ROOT}

COPY ../.. ${APP_ROOT}

RUN pip install --upgrade pip && \
    pip install -r ${APP_ROOT}/requirements.in
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8000

COPY compose/staging/entrypoint.sh ${APP_ROOT}

ENTRYPOINT ${APP_ROOT}/entrypoint.sh