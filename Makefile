.PHONY: build build-server build-client build-agent test clean install plugins \
        docker-build docker-build-server docker-build-agent docker-build-client \
        docker-push docker-up docker-down docker-logs

# Build variables
BINARY_NAME=orion-belt
BUILD_DIR=bin
PLUGIN_DIR=plugins
BUILD_DIR_PLUGINS=bin/plugins
PLUGINS := audit-logger notification
GO=go
GOFLAGS=-v

# Docker variables
DOCKER_REGISTRY ?=
DOCKER_IMAGE ?= orion-belt
DOCKER_TAG ?= latest
DOCKER_DIR=docker
DOCKERFILE=$(DOCKER_DIR)/Dockerfile
DOCKERFILE_AGENT=$(DOCKER_DIR)/Dockerfile.agent

# Helper to prefix image name with registry if set
ifdef DOCKER_REGISTRY
  IMAGE_PREFIX=$(DOCKER_REGISTRY)/$(DOCKER_IMAGE)
else
  IMAGE_PREFIX=$(DOCKER_IMAGE)
endif

# Build all components
build: build-server build-client build-admin build-agent

# Build server
build-server:
	@echo "Building server..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-server ./cmd/server

# Build client
build-client:
	@echo "Building client..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/osh ./cmd/osh
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/ocp ./cmd/ocp

# Build admin
build-admin:
	@echo "Building admin..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/oadmin ./cmd/oadmin

# Build agent
build-agent:
	@echo "Building agent..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-agent ./cmd/agent

# Run tests
test:
	$(GO) test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out

# Install binaries to $GOPATH/bin
install: build
	@echo "Installing..."
	@cp $(BUILD_DIR)/$(BINARY_NAME)-server $(GOPATH)/bin/
	@cp $(BUILD_DIR)/$(BINARY_NAME)-agent $(GOPATH)/bin/
	@cp $(BUILD_DIR)/osh $(GOPATH)/bin/
	@cp $(BUILD_DIR)/ocp $(GOPATH)/bin/

# Run server
run-server: build-server
	$(BUILD_DIR)/$(BINARY_NAME)-server

# Run tests with coverage
test-coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out

# Format code
fmt:
	$(GO) fmt ./...

# Lint code
lint:
	golangci-lint run

# Download dependencies
deps:
	$(GO) mod download
	$(GO) mod verify

# Update dependencies
update-deps:
	$(GO) get -u ./...
	$(GO) mod tidy

# plugins section
plugins: $(BUILD_DIR_PLUGINS)
	@echo "Building plugins..."
	@for plugin in $(PLUGINS); do \
		echo "Building $$plugin.so..."; \
		$(GO) build -buildmode=plugin -o $(BUILD_DIR_PLUGINS)/$$plugin.so $(PLUGIN_DIR)/$$plugin/main.go || exit 1; \
	done
	@echo "Plugins built successfully"

$(BUILD_DIR_PLUGINS):
	@mkdir -p $(BUILD_DIR_PLUGINS)

# ────────────────────────────────────────────────────────────
# Docker targets
# ────────────────────────────────────────────────────────────

# Build server image
docker-build-server:
	@echo "Building server image: $(IMAGE_PREFIX)-server:$(DOCKER_TAG)..."
	docker build \
		--file $(DOCKERFILE) \
		--tag $(IMAGE_PREFIX)-server:$(DOCKER_TAG) \
		.

# Start the full stack via Docker Compose
docker-up:
	docker compose -f $(DOCKER_DIR)/docker-compose.yml up -d
	@echo "Stack is up. Server SSH: localhost:2222  API: localhost:8080"

# Stop the stack
docker-down:
	docker compose -f $(DOCKER_DIR)/docker-compose.yml down

# Tail logs (optionally filter: make docker-logs SERVICE=server)
docker-logs:
	docker compose -f $(DOCKER_DIR)/docker-compose.yml logs -f $(SERVICE)