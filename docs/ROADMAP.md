# Orion Belt — Development Roadmap

## Current Status

**Version:** Alpha v0.4 (MFA, admin UI, OpenFGA, recording encryption)
**Status:** Phase 1 hardening complete on master through v0.3.1; v0.4 features on `feature/v0.4-mfa-ui-openfga-recording`

## What Orion Belt Is

Orion Belt is a lightweight, self-hosted Privileged Access Management (PAM) system built in Go. It implements a bastion host pattern using *reverse SSH tunnels*, fine-grained access control (ReBAC), session recording, and an approval-based workflow for temporary access. The goal is secure, auditable access to infrastructure with no open inbound ports.

---

## Done

### v0.1 — Core System

#### Gateway Server

* **SSH Proxy (Port 2222)**
  - [x] Full SSH implementation using **golang.org/x/crypto/ssh**
  - [x] Public-key auth backed by PostgreSQL
  - [x] Concurrent multi-session handling
  - [x] Direct-tcpip forwarding to machines
  - [x] Full session lifecycle support

* **REST API (Port 8080)**
  - [x] Endpoints for user/machine/permission management
  - [x] Access request endpoints
  - [x] Session listing and audit log retrieval
  - [x] Agent registration
  - [x] Built with Gin and produces structured JSON responses

* **Database Layer**
  - [x] PostgreSQL backend with well-defined schema
  - [x] Interface-based abstraction
  - [x] Connection pooling
  - [x] Transaction support

* **Session Recording**
  - [x] Captures all SSH I/O with timestamps
  - [x] Structured, replay-ready format
  - [x] Stored by session ID

#### Agent

- [x] Reverse SSH agent that dials the gateway
- [x] Auto-reconnect functionality
- [x] Machine registration/heartbeat
- [x] Agent key authentication

#### Client Tools

* **osh / ocp**
  - [x] Authenticates with the gateway
  - [x] Proxies to target machines / SCP via gateway

### Security & Access Control (v0.1)

- [x] SSH public key auth for users/agents
- [x] Relationship-Based Access Control (ReBAC)
- [x] Machine-specific grants, permission expiry, admin bypass
- [x] Temporary access request/approve/reject workflow
- [x] Audit logging via API

### v0.2 — API & Auth Foundations

- [x] REST API surface expansion
- [x] API key generation, hashing, validation, revoke/delete
- [x] Session-token auth for HTTP clients
- [x] `login/key` (SSH pubkey → API key) for CLI tools

### v0.3 — Client Workflows & Plugins

- [x] Dynamic `.so` plugin loader with lifecycle hooks
- [x] Slack notification plugin
- [x] Audit-logger plugin
- [x] Remote user specification (`user@machine`, `--user`, `remote_users`)
- [x] Client machine listing (`osh --list`)
- [x] Access request creation + polling from client
- [x] Admin CLI (`oadmin`) for approve/reject
- [x] Docker Compose local-dev stack (merged on master post-tag)

### Phase 1 Hardening (v0.3.1 — current)

* **SSH Host Key Verification**
  - [x] Replace `InsecureIgnoreHostKey` in client (`osh`/`ocp`)
  - [x] Replace `InsecureIgnoreHostKey` in agent
  - [x] TOFU (Trust On First Use) via `strict_host_key_checking: ask`
  - [x] Strict mode (`yes`) and insecure opt-out (`no`)
  - [x] Known hosts file management (`auth.known_hosts`)

* **API Authentication & Authorization**
  - [x] JWT bearer tokens (`Authorization: Bearer`, `POST /api/v1/public/login/token`)
  - [x] API key generation, validation, and management (from v0.2)
  - [x] Database-backed API key validation
  - [x] Rate limiting per user/IP on protected routes
  - [x] Login requires SSH public key verification (no passwordless username login)

* **Notifications & Integrations**
  - [x] Slack Incoming Webhook plugin
  - [x] SMTP email notification plugin
  - [x] Generic webhook notification plugin
  - [x] Access-request / access-granted hooks fired from API
  - [x] Post-auth hook fired after successful SSH auth
  - [ ] Template system for notification content
  - [ ] User notification preferences management

* **Agent Command Interface**
  - [x] Agent control commands: `orion:ping`, `orion:health`, `orion:status`, `orion:info`
  - [x] Admin API: `GET /api/v1/admin/agents/connected`, `POST /api/v1/admin/agents/:machine_id/command`
  - [ ] Richer remote management (reload config, drain, update)

* **Observability**
  - [x] Prometheus-format metrics at `GET /metrics`
  - [ ] OpenTelemetry tracing
  - [ ] Alerting system

---

### v0.4 — MFA, Admin UI, OpenFGA, Recording Hardening

* **MFA (TOTP)**
  - [x] TOTP enrollment (`POST /mfa/enroll`, `/mfa/confirm`)
  - [x] Backup codes (hashed, single-use)
  - [x] Disable with MFA proof
  - [x] Enforcement on API login paths (`totp_code`)
  - [x] `auth.mfa_required` blocks SSH until enrolled
  - [ ] WebAuthn / hardware keys

* **Web Admin UI**
  - [x] Embedded SPA at `/ui/` (login, dashboard, approvals, machines, sessions, users, audit, MFA)
  - [x] Session playback in browser
  - [ ] Richer permission editor / machine CRUD forms

* **OpenFGA**
  - [x] Optional OpenFGA HTTP client (`auth.openfga`)
  - [x] Check on permission paths with ReBAC fallback
  - [x] Write/delete tuples on grant/revoke
  - [x] Example model in `docs/openfga-model.fga`

* **Recording encryption & retention**
  - [x] AES-256-GCM at-rest encryption (`recording.encryption_key`)
  - [x] Decrypt on playback API
  - [x] Retention enforcement loop (`recording.retention_days`)
  - [ ] Compression

---

## Still open (post-v0.4)

- [ ] Certificate lifecycle / SSH CA
- [ ] HashiCorp Vault integration
- [ ] Structured logs (Loki/ELK)
- [ ] OpenTelemetry tracing
- [ ] Notification templates / user preferences
- [ ] WebAuthn

## Roadmap — Later Phases

### Phase 2 — Advanced Features

- [ ] HA clustering and DB replication
- [ ] JIT (Just-In-Time) access
- [ ] Risk-based access policies
- [ ] RBAC complementary to ReBAC
- [ ] Live session monitoring tools
- [ ] Command filtering and blocking
- [ ] Identity provider integrations (LDAP/SAML/OIDC)
- [ ] SIEM integrations
- [ ] Ticketing system integrations

### Phase 3 — Security & Compliance

- [ ] Compliance reporting (SOC2, HIPAA, PCI)
- [ ] Declarative policy engine
- [ ] Proxy extensions for network segmentation
- [ ] Usage analytics
- [ ] Security analytics and anomaly detection

### Phase 4 — Advanced Capabilities

- [ ] Support for RDP / VNC / Kubernetes API / database proxies
- [ ] Workflow automation
- [ ] AI/ML-powered access analytics
- [ ] CLI improvements
- [ ] SDKs (Go, Python, TypeScript)

---

## Technical Debt & Improvements

**Code Quality**

- [ ] Hit ~80% unit test coverage
- [ ] Integration test suites
- [ ] End-to-end test suites
- [ ] Performance benchmarks
- [ ] Architecture Decision Records (ADRs)

**Refactoring**

- [ ] Error handling standardization
- [ ] Logging standardization
- [ ] Config validation improvements
- [ ] Complete remaining machine CRUD admin stubs

**Documentation**

- [ ] OpenAPI/Swagger specification
- [ ] Deployment guides
- [ ] Security hardening guides
- [x] Plugin development guides
- [x] Contributing guidelines
- [x] Architecture documentation

---

## Version Milestones

* **v0.1:** Core SSH proxy, recording, ReBAC
* **v0.2:** REST API, API keys / session auth
* **v0.3:** Plugins, remote users, client access workflow, oadmin
* **v0.3.1:** Host key verification, JWT, rate limits, email/webhook plugins, agent commands, Prometheus metrics
* **v0.4:** MFA (TOTP), embedded admin UI, OpenFGA optional authz, recording encryption + retention
* **v0.5:** HA, IdP integrations, live session monitoring, WebAuthn
* **v1.0:** Multi-protocol support, SDKs, compliance-ready

---

## Contribution

Open source — focus areas: WebAuthn, IdP integrations, recording compression, HA, docs, and tests.

**High-priority contribution areas (next):**
- WebAuthn / hardware MFA
- Identity provider integrations (OIDC/SAML)
- Live session monitoring
- SSH certificate authority
- OpenAPI specification

---

## Notes

This is a living roadmap. Git tags (`v0.1.0`–`v0.3.0`) and merged PRs #1–#5 are the source of truth for shipped work; this document tracks remaining gaps.

**Last Updated:** July 2026  
**Maintainer:** Mohamed Zrouga ([@zrougamed](https://github.com/zrougamed))
