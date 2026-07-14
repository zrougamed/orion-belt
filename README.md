# Orion-Belt

[![Website](https://img.shields.io/badge/website-orion--belt.dev-0B3D5C?style=flat-square)](https://orion-belt.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commons%20Clause-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/zrougamed/orion-belt?style=flat-square)](go.mod)
[![Release](https://img.shields.io/github/v/release/zrougamed/orion-belt?include_prereleases&style=flat-square)](https://github.com/zrougamed/orion-belt/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/zrougamed/orion-belt/ci.yml?branch=master&style=flat-square&label=CI)](https://github.com/zrougamed/orion-belt/actions)


**Enterprise-grade privileged access — open source and self-hosted.**

**Orion-Belt** is an open-source SSH/SCP bastion and PAM gateway that gives teams the capabilities usually locked behind commercial products: **SSH Certificate Authority**, **session recording & replay**, **ReBAC / OpenFGA authorization**, **MFA (TOTP + WebAuthn)**, **JIT temporary access with approvals** (including ChatOps), and a **role-aware web console** — without exposing target networks.

Agents dial **out** over reverse SSH, so you eliminate inbound firewall holes. You keep control of data and deployment; the community gets the full source.

> Free to use, modify, and self-host — including for internal commercial use — under [Apache 2.0 + Commons Clause](LICENSE). The Clause withholds only the right to **sell** Orion Belt (or a hosted service whose value derives substantially from it) as a product. See [orion-belt.dev](https://orion-belt.dev).

> Status: **v1.0.0** — stable SSH PAM: CA, MFA, JIT, ReBAC, recording (+ compression / live watch), permissions editor, notification prefs, permissions editor, recording compression, live session watch, notification prefs/templates, JIT polish, JSON/Prometheus observability docs, password+TOTP + WebAuthn, SSH Certificate Authority, challenge-response login, plugin platform with live UI config, chatops approvals, OpenSSH clients, role-aware web console, OpenFGA, native packages, OpenAPI, GPG-signed repos.

![Orion-Belt](assets/banner-2.png)


## Why Orion-Belt?

Traditional SSH and VPN-based access have limitations:

- Long-lived credentials
- No native approval workflow
- Limited auditability
- Broad network access instead of per-machine access
- Enterprise PAM features trapped in proprietary licensing and SaaS lock-in

Orion-Belt solves this by:
- Eliminating inbound firewall rules using **reverse SSH tunnels**
- Enforcing **fine-grained, relationship-based access control**
- Supporting **temporary, approval-based access** (API, UI, and ChatOps)
- Recording **every session for audit and replay**
- Issuing **short-lived SSH certificates** instead of standing keys (optional SSH CA)
- Acting as a single, centralized access gateway you **run yourself**

## Orion-Belt in Action

![Orion-Belt demo](assets/orion-belt-in-action.gif)

## Features

- **Server Mode**: SSH/SCP tunneling server with session recording
- **Client Mode**: CLI tools (`osh`, `ocp`, `oadmin`) for connecting and approvals
- **OpenSSH clients**: Vanilla `ssh` via `user+machine@gateway` (no `osh` required) — see [openssh-clients.md](docs/openssh-clients.md)
- **Agent Mode**: Runs on target machines to receive connections
- **ReBAC**: Relationship-based access control for authorized users
- **Temporary Access**: Request-based temporary access with admin approval
- **Session Recording**: Complete session recording and audit trails (optional AES-at-rest, gzip compression, retention; live watch for active sessions)
- **Plugin System**: Built-in plugins (audit logger, Slack/email/webhook notifications, chatops access-request approvals for Slack/Discord/Teams/Rocket.Chat) — enable and configure live from the web console, no restart or YAML editing
- **Host Key Verification**: TOFU / known_hosts, or Host-CA trust when SSH CA is enabled
- **SSH CA**: Short-lived User certs for operators + Host certs for gateway/agents — [docs/SSH_CA.md](docs/SSH_CA.md)
- **API Auth**: API keys, session tokens, JWT; pubkey login requires challenge-response proof-of-possession; optional password + TOTP
- **MFA**: TOTP + YubiKey/FIDO2 (WebAuthn) for the web console; FIDO SSH keys (`sk-*`)
- **Web console**: Role-aware `/ui` with live terminal, files, sessions playback/watch, audit, users/machines, notification bell (see [SRS-UI.md](docs/SRS-UI.md))
- **OpenAPI**: Full HTTP/WS spec — [docs/openapi/openapi.yaml](docs/openapi/openapi.yaml) / `GET /api/v1/openapi.yaml`
- **Versioning**: `orion-belt-server --version`, `/health`, `/api/v1/version`, UI chrome
- **OpenFGA**: Optional external authorization with ReBAC fallback
- **Metrics & logs**: Prometheus `/metrics` + JSON slog (see [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md)); hardening checklist in [docs/DEPLOYMENT_HARDENING.md](docs/DEPLOYMENT_HARDENING.md)
- **Packaging**: deb/rpm/apk + GPG-signed APT/RPM repos
- **Database Agnostic**: Interface-based database layer for easy switching

## Architecture

```mermaid
flowchart TB
  subgraph Clients
    CLI["osh / ocp / oadmin"]
    OpenSSH["OpenSSH ssh<br/>user+host@gw"]
    UI["Web /ui<br/>terminal"]
  end

  GW["Gateway<br/>SSH :2222 · HTTP :8080"]
  Rec["Session recording · ReBAC/OpenFGA · MFA · SSH CA"]
  Agent["Target agent"]

  CLI --> GW
  OpenSSH --> GW
  UI --> GW
  GW --> Rec
  GW -->|"reverse SSH (agents)"| Agent
```

## Roadmap

**Current Status:** **v1.0.0** — SSH PAM we’re willing to call stable (`/api/v1` compatibility notes, ops docs, `make release-smoke`).

**Shipped:** SSH proxy, ReBAC, recording (+ compression/encryption/retention + live watch), REST API, JWT/API keys, plugins (compiled-in + live UI config), chatops approvals, remote users, host-key / Host-CA verification, metrics + JSON logs, TOTP + WebAuthn/FIDO + password login, OpenSSH agentless clients, role-aware web console (permissions editor, notification prefs), optional OpenFGA, native packages + GPG-signed repos, OpenAPI, SSH Certificate Authority, JIT access requests.

**Next:** OIDC, HA, other protocols, SDKs, compliance packs. See [V1_RELEASE_CRITERIA.md](docs/V1_RELEASE_CRITERIA.md) / [ROADMAP.md](docs/ROADMAP.md).

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

### Docker (fastest way to try it)

**One command** — generates secrets, starts the server, and bootstraps the
first admin login for you:
```bash
./scripts/docker-quickstart.sh
```
It prints the admin username + public key to log in with at the end. Safe to
re-run (skips anything already done).

**Or step by step**, if you'd rather see/control each piece:
```bash
cp .env.server.example .env.server
# fill in POSTGRES_PASSWORD and ORION_JWT_SECRET (openssl rand -hex 32)
docker compose -f docker-compose.server.yml --env-file .env.server up -d
```
There's no self-service "create account" page in the web console (it's
SSH-public-key auth, not passwords) — the first admin is created once via the
CLI, from a public key you already hold:
```bash
ssh-keygen -t ed25519 -f admin-key -N ""   # or reuse an existing key
docker compose -f docker-compose.server.yml --env-file .env.server exec -T \
  -e ORION_SETUP_ADMIN_NAME=admin -e ORION_SETUP_ADMIN_EMAIL=admin@localhost \
  -e ORION_SETUP_ADMIN_KEY="$(cat admin-key.pub)" \
  server /app/orion-belt-server -c /etc/orion-belt/config.generated.yaml setup
```
Then open http://localhost:8080/ui and sign in with username `admin` and the
contents of `admin-key.pub` as the public key.

Once logged in, register an agent from the web console ("Add agent") and run
it on the machine you want to manage — it dials out to the server, so no
inbound ports need to be opened on that host:
```bash
# save the private key the "Add agent" page gives you as ./agent-key (chmod 600)
cp .env.agent.example .env.agent
# fill in ORION_SERVER_HOST and ORION_AGENT_NAME (must match what you registered)
docker compose -f docker-compose.agent.yml --env-file .env.agent up -d
```

Equivalent `make` targets: `docker-up` / `docker-down` / `docker-logs` for the
server, `docker-agent-up` / `docker-agent-down` for the agent.

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
├── web/              # React console → build → embed at /ui
│   ├── ui/           # Vite + React source
│   ├── static/       # built assets (go:embed into server)
│   └── embed.go      # serves /ui/ from the server binary
├── docs/
│   ├── openapi/      # OpenAPI 3.0 (embedded + served)
│   ├── SRS-UI.md     # Web console requirements (as implemented)
│   └── API/          # Postman + Swagger how-to
├── packaging/        # nfpm configs, systemd, GPG keys (public)
├── plugins/          # Slack, email, webhook, audit-logger, chatops-access-request
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

Apache License 2.0 with the [Commons Clause](https://commonsclause.com/) — see
[LICENSE](LICENSE). Orion Belt ships **enterprise PAM capabilities as open source**
you can audit and self-host. You may use, modify, and run it internally (including
commercially); the Clause only withholds selling Orion Belt itself, or a hosted
service whose value derives substantially from it, as a product. Details and positioning:
[orion-belt.dev](https://orion-belt.dev).

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
