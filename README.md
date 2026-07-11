# Orion-Belt

**Orion-Belt** is an open-source, secure SSH/SCP bastion system designed for **controlled access to infrastructure without exposing networks**.

It provides **reverse SSH tunneling**, **relationship-based access control (ReBAC)**, **temporary access workflows**, and **full session recording**, making it ideal for teams that need **auditable, time-bound, and approval-based access** to servers behind firewalls.

Think of it as a lightweight, self-hosted alternative to traditional bastion hosts or commercial access gateways — built with simplicity, auditability, and extensibility in mind.

> Status: **Alpha v0.4+** — MFA/WebAuthn, OpenSSH clients, role-aware web console, OpenFGA, recording encryption, native packages, OpenAPI, GPG-signed repos

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
- **OpenSSH clients**: Vanilla `ssh` via `user+machine@gateway` (no `osh` required) — see [openssh-clients.md](docs/openssh-clients.md)
- **Agent Mode**: Runs on target machines to receive connections
- **ReBAC**: Relationship-based access control for authorized users
- **Temporary Access**: Request-based temporary access with admin approval
- **Session Recording**: Complete session recording and audit trails (optional AES-at-rest + retention)
- **Plugin System**: Dynamic plugins (Slack, email, webhooks, audit logger)
- **Host Key Verification**: TOFU / known_hosts for clients and agents
- **API Auth**: API keys, session tokens, and JWT bearer tokens
- **MFA**: TOTP + YubiKey/FIDO2 (WebAuthn) for the web console; FIDO SSH keys (`sk-*`)
- **Web console**: Role-aware `/ui` with live terminal, files, sessions playback, audit, users/machines (see [SRS-UI.md](docs/SRS-UI.md))
- **OpenAPI**: Full HTTP/WS spec — [docs/openapi/openapi.yaml](docs/openapi/openapi.yaml) / `GET /api/v1/openapi.yaml`
- **Versioning**: `orion-belt-server --version`, `/health`, `/api/v1/version`, UI chrome
- **OpenFGA**: Optional external authorization with ReBAC fallback
- **Metrics**: Prometheus-format `/metrics` endpoint
- **Packaging**: deb/rpm/apk + GPG-signed APT/RPM repos
- **Database Agnostic**: Interface-based database layer for easy switching

## Architecture

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  osh / ocp   │  │ OpenSSH ssh  │  │  Web /ui     │
│  oadmin CLI  │  │ user+host@gw │  │  terminal    │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                  │
       └────────────┬────┴──────────────────┘
                    │ SSH :2222  /  HTTP :8080
                    ▼
             ┌──────────────┐
             │    Gateway   │──► Session recording, ReBAC/OpenFGA, MFA
             └──────┬───────┘
                    │ reverse SSH (agents)
                    ▼
             ┌──────────────┐
             │ Target agent │
             └──────────────┘
```

## Roadmap

**Current Status:** Alpha **v0.4** is on `master` (PR #7). Packaging / CVE gate / multi-distro lab work lands next.

**Shipped (through v0.4):** SSH proxy, ReBAC, recording (+ encryption/retention), REST API, JWT/API keys, plugins, remote users, host-key verification, metrics, TOTP + WebAuthn/FIDO, OpenSSH agentless clients, role-aware web console (terminal + files), optional OpenFGA.

**Next:** Ship packaging/CVE/lab/OpenAPI as v0.5; then HA, IdP (OIDC/SAML), live session monitoring, SSH CA, recording compression.

## Packaging & labs

- **Native packages (deb/rpm/apk):** `make packages` — see [docs/PACKAGING.md](docs/PACKAGING.md)
- **Signed repos:** `make packaging-key && ORION_REQUIRE_SIGN=1 make repos`
- **Zero-CVE gate:** `make cve` (Go 1.26.5 + govulncheck)
- **API docs:** [OpenAPI](docs/openapi/openapi.yaml) · [Swagger how-to](docs/API/README.md)
- **UI SRS:** [docs/SRS-UI.md](docs/SRS-UI.md)
- **Multi-distro lab:** Docker Compose or QEMU — see [lab/README.md](lab/README.md)
- **E2E / QA plan (QEMU):** [docs/E2E_TEST_PLAN.md](docs/E2E_TEST_PLAN.md)

```bash
make lab-qemu-start    # clean → boot → admin → agents → RBAC users → SSH howto
```

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

### From source

```bash
# Requires Go 1.26.5+ (see go.mod toolchain)
git clone https://github.com/zrougamed/orion-belt.git
cd orion-belt
make build
```

### From packages (deb / rpm / apk)

```bash
make packages   # writes dist/*.deb *.rpm *.apk
./scripts/gen-packaging-key.sh && ORION_REQUIRE_SIGN=1 make repos   # signed apt/rpm/apk trees
# Debian/Ubuntu:
sudo apt install ./dist/orion-belt_*_amd64.deb ./dist/orion-belt-agent_*_amd64.deb
# RHEL/Rocky/Fedora/openSUSE:
sudo rpm -Uvh dist/orion-belt-*.rpm dist/orion-belt-agent-*.rpm
# Alpine:
sudo apk add --allow-untrusted ./dist/orion-belt_*.apk ./dist/orion-belt-agent_*.apk
```

See [docs/PACKAGING.md](docs/PACKAGING.md) for systemd units, GPG-trusted repos, and release tagging.

### Or build individually

```bash
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
├── cmd/              # server, agent, osh, ocp, oadmin
├── pkg/              # server, client, agent, api, auth, authz, recording, …
├── web/              # embedded admin/ops console (/ui)
├── docs/
│   ├── openapi/      # OpenAPI 3.0 (embedded + served)
│   ├── SRS-UI.md     # Web console requirements (as implemented)
│   └── API/          # Postman + Swagger how-to
├── packaging/        # nfpm configs, systemd, GPG keys (public)
├── plugins/          # Slack, email, webhook, audit-logger
├── lab/              # Compose + QEMU multi-distro labs
├── config/           # example YAML
└── docker/           # Compose + images
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
- Session recordings can be AES-GCM encrypted at rest (`recording.encryption_key`)
- ReBAC (and optional OpenFGA) enforce fine-grained access control
- MFA: TOTP and/or WebAuthn (YubiKey); SSH supports FIDO `sk-*` keys
- Audit logs track access and changes
- Temporary access automatically expires

## Database Support

Currently supported databases:
- PostgreSQL

To switch databases, update the configuration and implement the `database.Store` interface if needed.

## License

Apache License 2.0 – see [LICENSE](LICENSE) file for details.

## Architecture

For a detailed architecture overview, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).  
Web console SRS: [SRS-UI.md](docs/SRS-UI.md).  
HTTP API: [openapi.yaml](docs/openapi/openapi.yaml).

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
