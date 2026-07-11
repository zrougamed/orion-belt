# Build stage
FROM golang:1.26.5-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build all components
RUN make build

# Server image
FROM alpine:latest AS server

RUN apk add --no-cache ca-certificates openssh-keygen

WORKDIR /app

COPY --from=builder /build/bin/orion-belt-server /app/
COPY --from=builder /build/config/server.example.yaml /config/config.yaml

# Create directories
RUN mkdir -p /var/lib/orion-belt/recordings /etc/orion-belt

# Generate SSH host key
RUN ssh-keygen -t rsa -f /etc/orion-belt/ssh_host_key -N ""

EXPOSE 2222

CMD ["/app/orion-belt-server", "-c", "/config/config.yaml"]
