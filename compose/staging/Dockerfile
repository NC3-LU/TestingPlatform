ARG PYTHON_VERSION
FROM python:${PYTHON_VERSION}
ARG DEBUG
ENV PYTHONUNBUFFERED 1

ENV APP_ROOT /var/www/testing_platform
WORKDIR ${APP_ROOT}

COPY ../../requirements.txt ${APP_ROOT}

RUN pip3 install -r ${APP_ROOT}/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8000

COPY ../.. ${APP_ROOT}
COPY compose/staging/entrypoint.sh ${APP_ROOT}

ENTRYPOINT [ "/var/www/testing_platform/entrypoint.sh" ]
