# Orion Belt — Development Roadmap

## Current Status

**Version:** Alpha v0.1
**Status:** Early development — core functionality is working, production hardening underway

## What Orion Belt Is

Orion Belt is a lightweight, self-hosted Privileged Access Management (PAM) system built in Go. It implements a bastion host pattern using *reverse SSH tunnels*, fine-grained access control (ReBAC), session recording, and an approval-based workflow for temporary access. The goal is secure, auditable access to infrastructure with no open inbound ports.

---

## Done (v0.1)

### Core System

#### Gateway Server

* **SSH Proxy (Port 2222)**
  - [x] Full SSH implementation using **golang.org/x/crypto/ssh**
  - [x] Public-key auth backed by PostgreSQL
  - [x] Concurrent multi-session handling
  - [x] Direct-tcpip forwarding to machines
  - [x] Full session lifecycle support

* **REST API (Port 8080)**
  - [x] ~40 endpoints for user/machine/permission management
  - [x] Access request endpoints
  - [x] Session listing and audit log retrieval
  - [x] Agent registration
  - [x] Built with Gin and produces structured JSON responses

* **Database Layer**
  - [x] PostgreSQL backend with well-defined schema
  - [x] Interface-based abstraction
  - [x] Connection pooling
  - [x] Transaction support
  - [x] Robust scanning/CRUD support

* **Session Recording**
  - [x] Captures all SSH I/O with timestamps
  - [x] Structured, replay-ready format
  - [x] Stored by session ID

#### Agent

- [x] Reverse SSH agent that dials the gateway
- [x] Auto-reconnect functionality
- [x] Machine registration/heartbeat
- [x] Agent key authentication
- [x] Integration with the local SSH daemon

#### Client Tools

* **osh (SSH Client)**
  - [x] Authenticates with the gateway
  - [x] Proxies to target machines
  - [ ] Implement proper SSH host key verification (currently using InsecureIgnoreHostKey)
  - [ ] Implement API call to request access
  - [ ] Implement API call to list machines

* **ocp (SCP Client)**
  - [x] Secure file transfers via the gateway
  - [ ] Implement proper SSH host key verification (currently using InsecureIgnoreHostKey)

### Security & Access Control

* **Authentication**
  - [x] SSH public key auth for users/agents
  - [x] Validated against the database

* **Authorization (ReBAC)**
  - [x] Relationship-Based Access Control
  - [x] Machine-specific grants
  - [x] Permission expiry
  - [x] Admin bypass
  - [x] Pre-connection validation

* **Temporary Access Workflow**
  - [x] Request/approve/reject flow
  - [x] Time-limited access grants
  - [x] Status tracking

* **Audit Logging**
  - [x] Comprehensive logs for every action
  - [x] IPs, metadata, and timestamps
  - [x] Exposed via API

### Plugin System

- [x] Interface-based plugin architecture
- [x] Lifecycle and hook integration
- [x] Notification plugin scaffold
- [ ] Implement email notifications (SMTP) for session events
- [ ] Implement email notifications for access requests
- [ ] Add Slack integration for admin notifications
- [ ] Add admin notification system for access approvals
- [ ] Add user notification system for approvals/denials

### Deployment & Operations

- [x] YAML configs with environment templates for server/agent/clients
- [x] Docker multi-stage builds and Compose setups
- [x] PostgreSQL init/migration/test data scripts

### Testing & Tools

- [x] End-to-end testing lab using QEMU VMs
- [x] Connection flows verification
- [x] Recording verification
- [x] Diagnostic scripts for SSH and health checks

---

## In Progress — Enhancements

### Security Enhancements

* **MFA**
  - [x] TOTP framework in place
  - [ ] Enrollment UI
  - [ ] Backup codes
  - [ ] Enforcement

* **SSH Certificate Authority**
  - [ ] CA key management
  - [ ] Signing
  - [ ] Revocation

### API & Admin

* **API Authentication**
  - [ ] Implement JWT token-based authentication
  - [ ] API key generation and management
  - [ ] Database-backed API key validation
  - [ ] Rate limiting per key/user

* **Web Admin UI**
  - [ ] Dashboard
  - [ ] User/machine/permission management
  - [ ] Access approvals interface
  - [ ] Session playback
  - [ ] Auditing interface

### Notifications

- [ ] SMTP integration with template system
- [ ] Slack integration
- [ ] Generic webhook support
- [ ] User notification preferences

### Agent Enhancements

- [ ] Implement server command interface (currently TODO)
- [ ] Remote agent management and control
- [ ] Agent health monitoring and diagnostics

---

## Roadmap — Planned Phases

### Phase 1 — Production Hardening

**Security**

* **SSH Host Key Verification**
  - [ ] Implement proper host key verification in client (replace InsecureIgnoreHostKey)
  - [ ] Implement proper host key verification in agent (replace InsecureIgnoreHostKey)
  - [ ] Add host key fingerprint validation
  - [ ] TOFU (Trust On First Use) support
  - [ ] Known hosts management for agents and clients

* **API Authentication & Authorization**
  - [ ] Implement JWT token-based authentication for REST API
  - [ ] Add API key generation, validation, and management
  - [ ] Database-backed API key validation with scoping and expiration
  - [ ] Rate limiting and throttling per key/user
  - [ ] Complete authentication middleware implementation

* **Access Control Enhancements**
  - [ ] OpenFGA integration for fine-grained policies
  - [ ] Implement client-side API endpoints for access request workflows
  - [ ] Implement client-side API endpoints for machine listing
  - [ ] Enhanced MFA (WebAuthn/U2F, SMS, push)
  - [ ] Certificate lifecycle automation
  - [ ] HashiCorp Vault integration

**Notifications & Integrations**

* **Plugin System Completion**
  - [ ] Implement email notifications (SMTP) for session events
  - [ ] Implement email notifications for access requests
  - [ ] Add Slack integration for admin notifications
  - [ ] Add webhook support for custom integrations
  - [ ] Template system for notification content
  - [ ] User notification preferences management

* **Agent Command Interface**
  - [ ] Implement server command handling in agent
  - [ ] Remote agent management and control
  - [ ] Agent health monitoring and diagnostics

**Observability**

- [ ] Prometheus metrics
- [ ] OpenTelemetry tracing
- [ ] Alerting system

**Logging & Recordings**

- [ ] Structured logs (Loki/ELK)
- [ ] Session recording encryption
- [ ] Session recording compression
- [ ] Recording retention policies

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

- [ ] Support for RDP protocol
- [ ] Support for VNC protocol
- [ ] Support for Kubernetes API proxy
- [ ] Support for database proxies (PostgreSQL, MySQL, etc.)
- [ ] Workflow automation
- [ ] API gateway enhancements
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

**Performance**

- [ ] Connection pooling optimization
- [ ] Database query optimization
- [ ] Recording I/O optimization
- [ ] Concurrency tuning

**Refactoring**

- [ ] Error handling standardization
- [ ] Logging standardization
- [ ] Config validation improvements
- [ ] Dependency injection improvements
- [ ] Remove insecure host key callbacks (replace with proper verification)
- [ ] Complete TODO implementations across codebase

**Documentation**

- [ ] OpenAPI/Swagger specification
- [ ] Deployment guides
- [ ] Security hardening guides
- [ ] Plugin development guides
- [ ] Contributing guidelines
- [ ] Architecture documentation

---

## Outstanding TODOs by Component

### Client (`pkg/client/client.go`)
- [ ] Line 56: Implement proper SSH host key verification (replace InsecureIgnoreHostKey)
- [ ] Line 118: Implement API call to request access
- [ ] Line 131: Implement API call to list machines

### Agent (`pkg/agent/agent.go`)
- [ ] Line 82: Implement proper SSH host key verification (replace InsecureIgnoreHostKey)
- [ ] Line 361: Implement server command interface and handlers

### API (`pkg/api/`)
- [ ] api.go Line 55: Implement JWT or API keys authentication
- [ ] middleware.go Line 24: Implement proper authentication (JWT, API keys, etc.)
- [ ] middleware.go Line 33: Validate API key against database

### Plugins (`plugins/notification/notification.go`)
- [ ] Line 70: Send actual email notification for session events
- [ ] Line 78: Send actual email notification for access requests
- [ ] Line 86: Send notification to admins (Slack/webhook)
- [ ] Line 95: Send notification to users for approvals/denials

---

## Version Milestones

* **v0.2:** Host key verification, API auth (JWT/API keys), notification plugins (email/Slack), MFA enrollment, OpenFGA integration, basic web UI, Prometheus metrics, improved audit logging
* **v0.3:** HA clustering, LDAP/AD integration, SIEM integrations, advanced session management, agent command interface, live session monitoring
* **v0.4:** Risk-based access, command filters, JIT access, anomaly detection, compliance reporting
* **v1.0:** Multi-protocol support (RDP/VNC/K8s/DB), AI analytics, SDKs, SOC2 Type II certification-ready

---

## Contribution

Open source, community contributions welcome — focus areas include protocol support, integrations, plugins, docs, testing, and UI. See the contributing guide (TBD) for details.

**High-priority contribution areas:**
- Host key verification implementation
- API authentication (JWT/API keys)
- Notification plugin backends (SMTP, Slack, webhooks)
- Agent command interface
- Client API integration
- Web admin UI development
- OpenFGA policy integration

---

## Success Metrics

* **Security:** Zero critical vulnerabilities, full audit trails, proper host key verification, comprehensive access controls
* **Performance:** <100 ms auth latency, 1K+ concurrent sessions, optimized recording I/O
* **Reliability:** 99.9% uptime, <30 s failover in HA mode
* **Usability:** <5 min setup time, intuitive UX, comprehensive documentation
* **Compliance:** SOC2/HIPAA/PCI-ready with audit reports

---

## Notes

This is a living roadmap and will evolve with user feedback, security needs, and industry changes. All TODO items from the codebase are tracked here and will be addressed in upcoming releases.

**Last Updated:** January 2026  
**Maintainer:** Mohamed Zrouga ([@zrougamed](https://github.com/zrougamed))