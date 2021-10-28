ARG PYTHON_VERSION

FROM python:${PYTHON_VERSION}

ARG DEBUG

ENV DEBUG=False
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/

RUN pip3 install -r /app/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8000

VOLUME [ "/app/db", "/app/files" ]
COPY . /app/

ENTRYPOINT [ "/app/entrypoint.sh" ]
