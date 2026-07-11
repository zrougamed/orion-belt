# Orion-Belt

**Orion-Belt** is an open-source, secure SSH/SCP bastion system designed for **controlled access to infrastructure without exposing networks**.

It provides **reverse SSH tunneling**, **relationship-based access control (ReBAC)**, **temporary access workflows**, and **full session recording**, making it ideal for teams that need **auditable, time-bound, and approval-based access** to servers behind firewalls.

Think of it as a lightweight, self-hosted alternative to traditional bastion hosts or commercial access gateways — built with simplicity, auditability, and extensibility in mind.

> Status: **Alpha v0.3+** — core PAM works; Phase 1 hardening (host keys, JWT, metrics, notifications) underway

![Orion-Belt banner](assets/banner.png)


## Why Orion-Belt?

Traditional SSH and VPN-based access have limitations:

- Long-lived credentials
- No native approval workflow
- Limited auditability
- Broad network access instead of per-machine access

Orion-Belt solves this by:
- Eliminating inbound firewall rules using **reverse SSH tunnels**
- Enforcing **fine-grained, relationship-based access control**
- Supporting **temporary, approval-based access**
- Recording **every session for audit and replay**
- Acting as a single, centralized access gateway

## Orion-Belt in Action

![Orion-Belt demo](assets/orion-belt-in-action.gif)

## Features

- **Server Mode**: SSH/SCP tunneling server with session recording
- **Client Mode**: CLI tools (`osh`, `ocp`, `oadmin`) for connecting and approvals
- **Agent Mode**: Runs on target machines to receive connections
- **ReBAC**: Relationship-based access control for authorized users
- **Temporary Access**: Request-based temporary access with admin approval
- **Session Recording**: Complete session recording and audit trails
- **Plugin System**: Dynamic plugins (Slack, email, webhooks, audit logger)
- **Host Key Verification**: TOFU / known_hosts for clients and agents
- **API Auth**: API keys, session tokens, and JWT bearer tokens
- **Metrics**: Prometheus-format `/metrics` endpoint
- **Database Agnostic**: Interface-based database layer for easy switching

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client    │────────>│    Server    │────────>│   Machine   │
│  (osh/ocp)  │         │  (tunneling) │         │   (agent)   │
└─────────────┘         └──────────────┘         └─────────────┘
                              │
                              ├─> Session Recording
                              ├─> ReBAC Authorization
                              └─> Access Request Management
```

## Roadmap

**Current Status:** Alpha **v0.3.1** on master; **v0.4** adds MFA, admin UI, OpenFGA, and recording encryption.

**Shipped:** SSH proxy, ReBAC, session recording, REST API + API keys/JWT, plugins, remote users, client workflows, Docker Compose, host-key verification, metrics.

**v0.4:** TOTP MFA, embedded `/ui` admin console, optional OpenFGA, AES recording encryption + retention.

See [ROADMAP.md](docs/ROADMAP.md) for the complete plan and tag history.

## Components

### Server
- SSH/SCP tunneling
- Session recording and playback
- ReBAC authorization engine
- Temporary access request handling
- Admin notification system

### Client (osh & ocp)
- `osh`: Orion-Belt SSH client
- `ocp`: Orion-Belt SCP client
- API integration with server

### Agent
- Runs on target machines
- Connects to server for reverse tunneling
- Receives and handles connections

## Installation

```bash
# Clone the repository
git clone https://github.com/zrougamed/orion-belt.git
cd orion-belt

# Build all components
make build

# Or build individually
make build-server
make build-client
make build-agent
```

## Configuration

### Server Configuration
```yaml
server:
  host: "0.0.0.0"
  port: 2222
  ssh_host_key: "/etc/orion-belt/host_key"
  
database:
  driver: "postgres"
  connection_string: "postgres://user:pass@localhost/orionbelt"
  
recording:
  enabled: true
  storage_path: "/var/lib/orion-belt/recordings"
  
auth:
  rebac_enabled: true
  allow_temp_access: true
  
notifications:
  smtp_host: "smtp.example.com"
  smtp_port: 587
  from_email: "orion-belt@example.com"
```

### Client Configuration
```yaml
server:
  host: "orion-belt.example.com"
  port: 2222
  api_endpoint: "https://orion-belt.example.com/api"
  
auth:
  key_file: "~/.ssh/id_rsa"
```

### Agent Configuration
```yaml
server:
  host: "orion-belt.example.com"
  port: 2222
  
agent:
  name: "web-server-01"
  tags:
    - "production"
    - "web"
```

## Usage

### Starting the Server
```bash
orion-belt server --config /etc/orion-belt/server.yaml
```

### Starting an Agent
```bash
orion-belt agent --config /etc/orion-belt/agent.yaml
```

### Using the Client (osh)
```bash
# Connect to a machine
osh machine-name

# Request temporary access
osh --request-access machine-name --duration 1h --reason "Emergency deployment"
```

### Using the Client (ocp)
```bash
# Copy file to remote machine
ocp local-file machine-name:/remote/path

# Copy from remote machine
ocp machine-name:/remote/file local-path
```

## Development

### Project Structure
```
orion-belt/
├── cmd/
│   ├── server/          # Server entry point
│   ├── client/          # Client (osh/ocp) entry point
│   └── agent/           # Agent entry point
├── pkg/
│   ├── server/          # Server implementation
│   ├── client/          # Client implementation
│   ├── agent/           # Agent implementation
│   ├── auth/            # ReBAC and authorization
│   ├── recording/       # Session recording
│   ├── database/        # Database interface and implementations
│   ├── api/             # API server and client
│   ├── plugin/          # Plugin system
│   └── common/          # Shared utilities
├── plugins/             # Plugin implementations
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

### Building from Source
```bash
go mod download
go build -o bin/orion-belt ./cmd/server
```

### Creating Plugins
For details see [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md).

## Security Considerations

- All connections are encrypted using SSH protocol
- Session recordings are encrypted at rest
- ReBAC ensures fine-grained access control
- Audit logs track all access and changes
- Temporary access automatically expires

## Database Support

Currently supported databases:
- PostgreSQL

To switch databases, update the configuration and implement the `database.Store` interface if needed.

## License

Apache License 2.0 – see [LICENSE](LICENSE) file for details.

## Architecture

For a detailed architecture overview, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## References

- [SSH Protocol](https://www.ssh.com/ssh/protocol/)
- [Go SSH Package (`golang.org/x/crypto/ssh`)](https://pkg.go.dev/golang.org/x/crypto/ssh)
- [Relationship-Based Access Control (ReBAC) Paper](https://dl.acm.org/doi/10.1145/1455518.1455520)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Secure Bastion Host Patterns](https://www.ssh.com/academy/bastion)
- [Reverse SSH Tunneling](https://www.ssh.com/academy/ssh/reverse-tunnel)
- [SSH Session Recording and Auditing](https://www.ssh.com/academy/ssh/session-recording)
