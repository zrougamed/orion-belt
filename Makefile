.PHONY: build build-server build-client build-agent test clean install plugins \
        docker-build docker-build-server docker-build-agent docker-build-client \
        docker-push docker-up docker-down docker-logs \
        cve packages repos lab-compose-up lab-compose-down lab-bootstrap-admin \
        lab-qemu-images lab-qemu-images-refresh lab-qemu-up lab-qemu-down lab-qemu-restart lab-qemu-test \
        lab-qemu-connect-agents lab-qemu-collect-keys lab-qemu-register-agents \
        lab-qemu-clean lab-qemu-start

# Build variables
BINARY_NAME=orion-belt
BUILD_DIR=bin
PLUGIN_DIR=plugins
BUILD_DIR_PLUGINS=bin/plugins
PLUGINS := audit-logger notification email-notifications webhook-notifications
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

# ────────────────────────────────────────────────────────────
# Security / packaging / labs
# ────────────────────────────────────────────────────────────

# Fail CI if any CVE affects our code or release binaries (0CVE gate)
cve:
	bash scripts/cve-check.sh

# Build deb/rpm/apk (+ binaries) into dist/
packages:
	bash scripts/package.sh

# Build static apt/rpm/apk repos under repos/ (after make packages)
repos:
	bash scripts/publish-repos.sh

lab-compose-up:
	bash lab/compose/bootstrap-keys.sh
	docker compose -f lab/compose/docker-compose.yml up -d --build
	@echo "Waiting for API, then bootstrapping admin…"
	bash lab/bootstrap-admin.sh
	@echo "Lab up. SSH gateway :2222  API :8080  UI :8080/ui"

lab-compose-down:
	docker compose -f lab/compose/docker-compose.yml down

# Create/reuse lab admin SSH key and register is_admin user for /ui login
lab-bootstrap-admin:
	bash lab/bootstrap-admin.sh

lab-qemu-images:
	bash lab/qemu/download-images.sh

lab-qemu-images-refresh:
	ORION_REFRESH_IMAGES=1 bash lab/qemu/download-images.sh

lab-qemu-up:
	bash lab/qemu/up.sh

lab-qemu-down:
	bash lab/qemu/down.sh

# Restart QEMU VMs in place (keep disks). Optional: VMS="server alpine"
lab-qemu-restart:
	bash lab/qemu/restart.sh $(VMS)

lab-qemu-test:
	bash lab/qemu/test-e2e.sh


# Collect keys → register on server → restart agents (optional: AGENTS="alpine debian")
lab-qemu-connect-agents:
	bash lab/qemu/connect-agents.sh $(AGENTS)

lab-qemu-collect-keys:
	bash lab/qemu/collect-agent-keys.sh

lab-qemu-register-agents:
	bash lab/qemu/register-agents.sh
	bash lab/qemu/restart-agents.sh


# Full wipe (VMs + images + credentials). Opt-out: KEEP_IMAGES=1 KEEP_CREDS=1
lab-qemu-clean:
	bash lab/qemu/clean.sh

# Clean (default) + boot + admin + agents + RBAC users + SSH howto
lab-qemu-start:
	bash lab/qemu/start.sh
