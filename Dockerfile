# Build stage
FROM golang:1.21-alpine AS builder

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
COPY --from=builder /build/config/server.example.yaml /app/config.yaml

# Create directories
RUN mkdir -p /var/lib/orion-belt/recordings /etc/orion-belt

# Generate SSH host key
RUN ssh-keygen -t rsa -f /etc/orion-belt/ssh_host_key -N ""

EXPOSE 2222

CMD ["/app/orion-belt-server", "-c", "/app/config.yaml"]

# Agent image
FROM alpine:latest AS agent

RUN apk add --no-cache ca-certificates openssh-client openssh-server openssh-keygen

WORKDIR /app

COPY --from=builder /build/bin/orion-belt-agent /app/
COPY --from=builder /build/config/agent.example.yaml /app/config.yaml
COPY --from=builder /build/scripts/agent-init.sh /app/agent-init.sh

# Make init script executable
RUN chmod +x /app/agent-init.sh

# Configure SSH server
RUN mkdir -p /var/run/sshd && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "root:password" | chpasswd

EXPOSE 22

# Use init script that generates keys and starts both sshd and agent
CMD ["/app/agent-init.sh"]

# Client image
FROM alpine:latest AS client

RUN apk add --no-cache ca-certificates openssh-client

WORKDIR /app

COPY --from=builder /build/bin/osh /app/
COPY --from=builder /build/bin/ocp /app/
COPY --from=builder /build/config/client.example.yaml /app/config.yaml

# Generate SSH key for client
RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N ""

CMD ["/bin/sh"]