IMAGE_NAME = "ghcr.io/katexochen/coco-fake-kbs"

.PHONY: container
container:
	DOCKER_BUILDKIT=1 docker build -f Containerfile -t $(IMAGE_NAME) .

.PHONY: push
push:
	docker push $(IMAGE_NAME)
