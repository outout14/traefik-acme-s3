EXTENSION ?= 
DIST_DIR ?= dist/
GOOS ?= linux
ARCH ?= x86_64
BUILDINFOSDET ?= 
IMAGE ?= tracs3:latest

SOFT_NAME    := tracs3
SOFT_VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo dev)
VERSION_PKG   = $(shell echo $(SOFT_VERSION) | sed 's/^v//g')
LICENSE       := AGPL-3
URL           := https://github.com/outout14/traefik-acme-s3/
DESCRIPTION   := traefik-acme-s3 manages ACME certificates in S3
BUILDINFOS     =  ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS        = '-X main.version=$(SOFT_VERSION) -X main.buildinfos=$(BUILDINFOS)'

OUTPUT_SOFT = $(DIST_DIR)$(SOFT_NAME)-$(SOFT_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test ./...

.PHONY: test-integration
test-integration:
	go test -tags integration ./integration/...

.PHONY: test-all
test-all: test test-integration

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)
	go clean -testcache

.PHONY: build
build: prepare
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_SOFT)

.PHONY: run 
run: build 
	$(OUTPUT_SOFT) $(ARGS)

.PHONY: docker-build
docker-build:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--output "type=docker,push=false" \
		--tag $(IMAGE) \
		.

.PHONY: docker-publish
docker-publish:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--platform linux/386,linux/amd64,linux/arm/v7,linux/arm64 \
		--output "type=image,push=true" \
		--tag $(IMAGE) \
		.
