.PHONY: build build-server build-client build-agent test clean install 

# Build variables
BINARY_NAME=orion-belt
BUILD_DIR=bin
GO=go
GOFLAGS=-v

# Build all components
build: build-server build-client build-agent

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

