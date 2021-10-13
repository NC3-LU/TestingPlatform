#!/bin/bash

python3 manage.py makemigrations authentication automation iot_inspector

python3 manage.py makemigrations

python3 manage.py migrate

python3 manage.py collectstatic --noinput

exec python3 manage.py runserver 0.0.0.0:8000
