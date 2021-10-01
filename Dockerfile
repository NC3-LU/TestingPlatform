FROM python:3.9

ARG DEBUG

ENV DEBUG=False
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/

RUN pip3 install -r /app/requirements.txt

EXPOSE 8000

VOLUME [ "/app/db" ]
COPY . /app/

ENTRYPOINT [ "/app/entrypoint.sh" ]
