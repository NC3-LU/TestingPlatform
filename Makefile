VERSION?=latest
IMAGE_NAME?=testing-platform:$(VERSION)

PYTHON_VERSION?=3.9

LOCAL_PORT?=8000

.PHONY: image run

image:
	docker build \
	  --build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
		-t $(IMAGE_NAME) .

run:
	docker run -it --rm \
			-p 127.0.0.1:$(LOCAL_PORT):8000 \
			-e DEBUG=True \
			-v$(PWD)/db:/app/db \
			-v$(PWD)/files:/app/files \
			$(IMAGE_NAME)

models:
	python manage.py graph_models --pydot -a -g -o docs/_static/app-models.png

openapi:
	python manage.py spectacular --format openapi > docs/_static/openapi.yml

generatepot:
	python manage.py makemessages -a --keep-pot

update:
	npm ci
	poetry install --only main
	python manage.py collectstatic
	python manage.py compilemessages
	python manage.py migrate

clean:
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete
