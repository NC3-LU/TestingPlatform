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
