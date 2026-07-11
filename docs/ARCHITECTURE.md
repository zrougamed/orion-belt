# Orion Belt - Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ osh/ocp  │  │  oadmin  │  │ OpenSSH ssh  │  │ Web console (/ui)   │  │
│  │   CLI    │  │   CLI    │  │ user+host@gw │  │ terminal + files    │  │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └──────────┬──────────┘  │
│       └─────────────┴───────┬───────┘                     │             │
│                             │ SSH :2222                   │ HTTP :8080  │
└─────────────────────────────┼─────────────────────────────┼─────────────┘
                              ▼                             ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        GATEWAY SERVER                                  │
│  ┌────────────────────────────┐   ┌─────────────────────────────────┐  │
│  │ SSH Proxy (2222)           │   │ REST API + /ui + /metrics       │  │
│  │ • Pubkey / FIDO sk-*       │   │ • JWT / API key / session       │  │
│  │ • user+machine routing     │   │ • WebAuthn / TOTP MFA           │  │
│  │ • Session + PTY forward    │   │ • Terminal WS / file browser    │  │
│  └───────────┬────────────────┘   └─────────────────────────────────┘  │
│              │                                                         │
│  ┌───────────▼────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Auth / Authz       │  │ Recorder     │  │ Plugins (Slack/email/  │  │
│  │ ReBAC + OpenFGA    │  │ AES optional │  │ webhook/audit)         │  │
│  │ Roles: admin/…     │  │ + retention  │  └────────────────────────┘  │
│  └───────────┬────────┘  └──────────────┘                              │
│              ▼                                                         │
│  ┌──────────────────────────────────────────────────────────┐          │
│  │ PostgreSQL: users, keys, webauthn, machines, sessions,   │          │
│  │ permissions, access_requests, audit_logs, api_keys, …    │          │
│  └──────────────────────────────────────────────────────────┘          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ reverse SSH (agents)
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
        ┌───────────┐         ┌───────────┐         ┌───────────┐
        │ Agent +   │         │ Agent +   │         │ Agent +   │
        │ local OS  │         │ local OS  │         │ local OS  │
        └───────────┘         └───────────┘         └───────────┘
```

## How It Works

### 1. Agent Registration & Connection
Agents establish persistent SSH connections to the gateway. Each agent authenticates with SSH keys and registers its machine. The gateway keeps reverse tunnels so targets need no inbound firewall rules.

### 2. Client Authentication
Clients authenticate with SSH public keys (including FIDO `sk-*` keys). Gateway identity may be encoded as `alice+web-01` for OpenSSH agentless interactive sessions. HTTP/API clients use API keys, session tokens, JWT, and optional TOTP/WebAuthn.

### 3. Connection Flow
1. Authenticate gateway user  
2. Check ReBAC (and OpenFGA if enabled)  
3. Open a **session** on the connected agent (`shell` / `exec`) — not `direct-tcpip` to remote sshd  
4. Record I/O; enforce remote-user ACL  

### 4. Session Recording
PTY **output** is recorded as a timed cast (asciinema-compatible v2, `.cast` under `recording.storage_path`). Recordings may be AES-GCM encrypted at rest, with retention cleanup for `.cast` / legacy `.txt` / `.rec` files. The web console replays casts in xterm (play/pause/seek).

### 5. Access Request Workflow
Users request temporary access; admins/operators approve via API, `oadmin`, or `/ui`. Grants are time-limited.

### 6. Web Console
Embedded SPA at `/ui` (roles: admin, operator, auditor, user) with approvals, live terminal (WebSocket, recorded as `source=web`), file browser, timed session playback, **Add agent** install scripts, audit trail, user/machine management, and build version display. See [SRS-UI.md](SRS-UI.md).

## Key Features

**Security**: SSH encryption, pubkey/FIDO auth, MFA, ReBAC/OpenFGA, session recording, audit logs.  
**Scalability**: Reverse-tunnel agents; single gateway for many machines.  
**Auditability**: Recordings, audit API, access-request history.  
**Flexibility**: Temporary grants, tags, plugins, OpenSSH and CLI clients.

## Data Flow Example

```
OpenSSH: ssh alice+web-01@gateway
    → Gateway pubkey (+ optional FIDO touch on client)
    → Parse target web-01 / remote user
    → Permission check
    → Agent session (PTY + shell)
    → I/O recorded
```

## Technology Stack

- **Language**: Go  
- **Database**: PostgreSQL  
- **Protocol**: SSH (`golang.org/x/crypto/ssh`), HTTP/WS (Gin)  
- **MFA**: TOTP (`pquerna/otp`), WebAuthn (`go-webauthn`)  
- **Architecture**: Bastion with reverse tunnels  
- **Deployment**: Docker Compose, native packages (deb/rpm/apk, GPG-signed repos), Alpine, or any Unix-like host
- **API docs**: OpenAPI 3.0 at `docs/openapi/openapi.yaml` / `GET /api/v1/openapi.yaml`

## Documentation index

| Doc | Status |
|-----|--------|
| [README.md](../README.md) | Current overview |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Current |
| [SRS-UI.md](SRS-UI.md) | Web console SRS (as implemented) |
| [openapi/openapi.yaml](openapi/openapi.yaml) | OpenAPI 3.0 (also `GET /api/v1/openapi.yaml`) |
| [API/README.md](API/README.md) | Swagger/Postman how-to |
| [PACKAGING.md](PACKAGING.md) | deb/rpm/apk + GPG-signed repos |
| [ROADMAP.md](ROADMAP.md) | Current |
| [SETUP.md](SETUP.md) | First-run |
| [openssh-clients.md](openssh-clients.md) | Current |
| [openfga-model.fga](openfga-model.fga) | Current |
| [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) | Plugin API |
| [SREVER-CLI.md](SREVER-CLI.md) | Server CLI (filename typo: “SREVER”) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Current |
| [E2E_TEST_PLAN.md](E2E_TEST_PLAN.md) | QEMU lab QA |

**Still open:** dedicated deployment hardening guide.
