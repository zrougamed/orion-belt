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
Recordings are buffered then written under `recording.storage_path`, optionally AES-GCM encrypted, with retention cleanup.

### 5. Access Request Workflow
Users request temporary access; admins/operators approve via API, `oadmin`, or `/ui`. Grants are time-limited.

### 6. Web Console
Embedded SPA at `/ui` (roles: admin, operator, auditor, user) with approvals, live terminal (WebSocket), and file browser.

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
- **Deployment**: Docker Compose, Alpine, or any Unix-like host  

## Documentation index

| Doc | Status |
|-----|--------|
| [README.md](../README.md) | Current (v0.4 overview) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Current |
| [ROADMAP.md](ROADMAP.md) | Current |
| [openssh-clients.md](openssh-clients.md) | Current |
| [openfga-model.fga](openfga-model.fga) | Current |
| [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) | Current for plugin API |
| [SREVER-CLI.md](SREVER-CLI.md) | Server CLI still accurate (filename typo: “SREVER”) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Generic; still valid |

**Not yet written:** OpenAPI/Swagger, deployment hardening guide (listed as debt in roadmap).
