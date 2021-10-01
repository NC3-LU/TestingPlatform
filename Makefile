VERSION?=0.1
IMAGE_NAME?=testing-platform:$(VERSION)

LOCAL_PORT?=8000

.PHONY: image run

image:
	docker build -t $(IMAGE_NAME) .

run:
	docker run -it --rm \
			-p 127.0.0.1:$(LOCAL_PORT):8000 \
			-e DEBUG=True \
			-v$(PWD)/db:/app/db \
			$(IMAGE_NAME)
