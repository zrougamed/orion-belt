# SRS — Orion Belt Web Console (UI)

**Document type:** Software Requirements Specification (UI)  
**Scope:** High-fidelity web console as implemented in `web/static/index.html`  
**Base URL:** `/ui/` (served by the gateway; redirects from `/` and `/admin`)  
**API:** `/api/v1/*` — see [openapi/openapi.yaml](openapi/openapi.yaml)  
**Status:** Implemented (Alpha, aligned with packaging / session-recording / versioning work)  
**Last updated:** July 2026

---

## 1. Purpose

The Orion Belt web console is the primary operator surface for privileged access: authenticate, request and approve access, open recorded web terminals, browse remote files, manage users/machines/agents, and inspect audit/session trails — without leaving the browser.

This SRS documents **what is implemented now**, not a future redesign. It is the acceptance baseline for UI regressions and for matching OpenAPI coverage.

---

## 2. Goals & non-goals

### Goals

- Single embedded SPA with role-aware navigation
- High-contrast, brand-led dark console (Instrument Sans + JetBrains Mono)
- First-class login with SSH pubkey, optional TOTP, and WebAuthn/FIDO2
- Live PTY terminal over WebSocket with session recording (`source=web`)
- Session playback, audit log browser, user/machine admin CRUD
- Visible **build version** so operators can confirm shipped features

### Non-goals (deferred)

- Fine-grained UI RBAC beyond role-gated nav (API still enforces ReBAC)
- Multi-page React/Vue app or design-system package
- Live shared session watching / collaborative cursors
- Full permission matrix editor UX (grants exist via API/`oadmin`; UI focuses on users, machines, requests)
- Light theme

---

## 3. Personas & roles

| Role | Nav access (implemented) | Notes |
|------|--------------------------|-------|
| **admin** | Dashboard, Setup, Requests, Machines, Terminal, Files, Sessions, Users, Agents, Audit, Security | Full console |
| **operator** | Same as admin | Approvals + admin API allowed |
| **auditor** | Dashboard, Sessions, Users (read), Audit, Security | No terminal/files/agents/setup |
| **user** | Machines, Terminal, Files, Sessions, Requests, Audit, Security | Self-service access + own security |

Role is taken from `user.role`, falling back to `is_admin → admin`, else `user`.

---

## 4. Information architecture

```
/ui/
├── Login stage (unauthenticated)
└── App shell (authenticated)
    ├── Side nav (role-filtered) + version in footer
    ├── Workspace top bar (product label + version)
    └── Views
        ├── Dashboard
        ├── Setup guide
        ├── Access requests
        ├── Machines
        ├── Terminal
        ├── Files
        ├── Sessions (+ playback)
        ├── Users
        ├── Agents
        ├── Audit
        └── Security (MFA | WebAuthn | SSH keys)
```

---

## 5. Visual design system (as shipped)

### 5.1 Brand & composition

- **Brand first:** Login hero is “Orion *Belt*” at display size; tagline secondary; version under tagline.
- **One composition:** Login is a centered stage (not a dashboard). App shell is nav + workspace.
- **Atmosphere:** Deep teal/charcoal base with grid + radial washes (not flat `#000`).
- **Accent:** Amber `#e8a54b` for CTAs and version chip; teal `#2dd4bf` for secondary signals.

### 5.2 Tokens (`:root`)

| Token | Value | Use |
|-------|-------|-----|
| `--bg-deep` / `--bg` | `#0a1214` / `#0e181c` | Page ground |
| `--bg-elev` / `--bg-panel` | `#152226` / `#1a2a30` | Panels |
| `--text` / `--muted` | `#e8f0f2` / `#8aa0a8` | Typography |
| `--accent` | `#e8a54b` | Primary actions |
| `--ok` / `--warn` / `--danger` | green / amber / red | Badges & toasts |
| `--font` | Instrument Sans | UI text |
| `--mono` | JetBrains Mono | IDs, times, paths, version |
| `--radius` | 12px | Panels / controls |
| `--nav-w` | 240px | Side nav |

### 5.3 Motion

- Login background drift (`@keyframes drift`, ~18s)
- Panel focus ring / border transitions (`--ease`)
- Toast show/hide
- Terminal connect status (live/off dot)

### 5.4 Components in use

- **Buttons:** primary / secondary / danger / small (`sm`) / block
- **Cards:** interaction or table containers (not decorative hero cards)
- **Badges:** status/source (`ok` / `warn` / `danger` / `neutral`)
- **Tables:** dense mono-friendly listings
- **Toasts:** transient success/error
- **Forms:** labeled fields, form-grid, selects
- **xterm.js** + FitAddon for terminal viewport

---

## 6. Functional requirements by screen

### 6.1 Login — FR-LOGIN

| ID | Requirement | Status |
|----|-------------|--------|
| FR-LOGIN-01 | Sign in with username + SSH public key | Done |
| FR-LOGIN-02 | Optional TOTP / backup code field | Done |
| FR-LOGIN-03 | WebAuthn / YubiKey / FIDO2 button (begin/finish) | Done |
| FR-LOGIN-04 | Persist `session_token` (localStorage + cookie) and optional JWT | Done |
| FR-LOGIN-05 | Show server build version from `GET /api/v1/version` | Done |
| FR-LOGIN-06 | Surface MFA required / enrollment errors clearly | Done |

**APIs:** `POST /public/login`, `POST /public/webauthn/login/*`, `GET /version`

### 6.2 Shell / chrome — FR-SHELL

| ID | Requirement | Status |
|----|-------------|--------|
| FR-SHELL-01 | Role-filtered side navigation | Done |
| FR-SHELL-02 | Show username, role pill, email in nav footer | Done |
| FR-SHELL-03 | Sign out → `POST /logout`, clear auth, return to login | Done |
| FR-SHELL-04 | Workspace bar shows product name + version | Done |
| FR-SHELL-05 | Nav footer shows version (mono) with commit/date tooltip | Done |
| FR-SHELL-06 | Responsive: nav stacks / workspace padding adjusts on narrow viewports | Done |

### 6.3 Dashboard — FR-DASH

| ID | Requirement | Status |
|----|-------------|--------|
| FR-DASH-01 | Stats: machines, active sessions, pending requests (as available) | Done |
| FR-DASH-02 | Mini table of active sessions (id, user, machine, remote, source, status) | Done |
| FR-DASH-03 | Setup incompleteness banner / deep-link when `setup/status` incomplete | Done |

**APIs:** `/machines`, `/sessions/active`, `/access-requests/pending`, `/setup/status`

### 6.4 Setup guide — FR-SETUP

| ID | Requirement | Status |
|----|-------------|--------|
| FR-SETUP-01 | Checklist for admin, agents, grants, connect paths | Done |
| FR-SETUP-02 | Reflect live `setup/status` steps and counts | Done |
| FR-SETUP-03 | Visible only to admin/operator nav | Done |

### 6.5 Access requests — FR-REQ

| ID | Requirement | Status |
|----|-------------|--------|
| FR-REQ-01 | List pending requests | Done |
| FR-REQ-02 | Create request (machine, remote users, reason, duration) | Done |
| FR-REQ-03 | Approve / reject for admin/operator | Done |

**APIs:** `/access-requests*`, `/admin/access-requests/:id/approve|reject`

### 6.6 Machines — FR-MACH

| ID | Requirement | Status |
|----|-------------|--------|
| FR-MACH-01 | List machines with activity badges | Done |
| FR-MACH-02 | Admin/operator create / edit / archive-or-delete | Done |
| FR-MACH-03 | Tags and hostname/port editable in admin flows | Done |

**APIs:** `/machines`, `/admin/machines`

### 6.7 Terminal — FR-TERM

| ID | Requirement | Status |
|----|-------------|--------|
| FR-TERM-01 | Select machine + remote user; Connect / Disconnect | Done |
| FR-TERM-02 | xterm.js PTY via `WS /terminal/ws?machine&user&token` | Done |
| FR-TERM-03 | Resize messages `{type:resize,cols,rows}` | Done |
| FR-TERM-04 | Cookie + query token auth for WebSocket | Done |
| FR-TERM-05 | Every successful connect creates recorded session `source=web` | Done (server) |
| FR-TERM-06 | Status indicator (connecting / live / disconnected / error) | Done |
| FR-TERM-07 | Disconnect on navigate away from Terminal | Done |

### 6.8 Files — FR-FILES

| ID | Requirement | Status |
|----|-------------|--------|
| FR-FILES-01 | Browse remote path for selected machine/user | Done |
| FR-FILES-02 | Download / upload / mkdir / delete | Done |
| FR-FILES-03 | Respect same ReBAC as terminal | Done (server) |

**APIs:** `/files/list|download|upload|mkdir`, `DELETE /files`

### 6.9 Sessions — FR-SESS

| ID | Requirement | Status |
|----|-------------|--------|
| FR-SESS-01 | List sessions with filters all / active / completed | Done |
| FR-SESS-02 | Columns: id, user, machine, remote, **source**, times, status | Done |
| FR-SESS-03 | Playback panel loads `/sessions/:id/content` | Done |
| FR-SESS-04 | Download recording from playback | Done |
| FR-SESS-05 | Distinguish `ssh` vs `web` source via badge | Done |

### 6.10 Users — FR-USER

| ID | Requirement | Status |
|----|-------------|--------|
| FR-USER-01 | List users with role, MFA, WebAuthn posture | Done |
| FR-USER-02 | Admin/operator create user (username, email, role, optional pubkey) | Done |
| FR-USER-03 | Inline edit email/role + save; delete | Done |

**APIs:** `/users`, `/admin/users`

### 6.11 Agents — FR-AGENT

| ID | Requirement | Status |
|----|-------------|--------|
| FR-AGENT-01 | Show connected agents | Done |
| FR-AGENT-02 | Register agent form (public register) | Done |
| FR-AGENT-03 | Send control command (e.g. `orion:info`) and show output | Done |

**APIs:** `/admin/agents/*`, `/public/register/agent`

### 6.12 Audit — FR-AUDIT

| ID | Requirement | Status |
|----|-------------|--------|
| FR-AUDIT-01 | Table of recent audit logs (actor, action, resource, IP, details) | Done |
| FR-AUDIT-02 | Refresh control | Done |

**API:** `GET /audit-logs?limit=`

### 6.13 Security — FR-SEC

| ID | Requirement | Status |
|----|-------------|--------|
| FR-SEC-01 | Tabs: MFA / WebAuthn / SSH keys | Done |
| FR-SEC-02 | MFA enroll → confirm with code; disable with code; status | Done |
| FR-SEC-03 | WebAuthn register / list / delete | Done |
| FR-SEC-04 | SSH key add / list / delete (supports sk-* types server-side) | Done |

---

## 7. Cross-cutting requirements

| ID | Requirement | Status |
|----|-------------|--------|
| FR-X-01 | All authenticated `fetch` calls send session/JWT headers as configured by `api()` helper | Done |
| FR-X-02 | 401 clears auth and returns to login | Done |
| FR-X-03 | Toasts for success/failure on mutating actions | Done |
| FR-X-04 | Escape HTML in rendered dynamic strings (`esc`) | Done |
| FR-X-05 | Version shown on login + shell without auth for `/version` | Done |
| FR-X-06 | Web terminal sessions appear under Sessions with playback | Done |

---

## 8. Non-functional requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | Load console without a separate frontend build step | Single embedded HTML/CSS/JS |
| NFR-02 | Usable on desktop and narrow mobile widths | Responsive CSS present |
| NFR-03 | Terminal usable at ≥80×24 with fit-on-resize | FitAddon |
| NFR-04 | No silent “connected but unrecorded” web sessions | Server refuses WS if recorder/session create fails |
| NFR-05 | Operators can verify binary features via version string | `/api/v1/version` + UI |

---

## 9. Acceptance checklist (QA)

1. Fresh load shows **login brand + version**.
2. Pubkey login lands on role-correct default view; version visible in bar/footer.
3. WebAuthn login works when credentials registered.
4. Open **Terminal** → connect → type → disconnect → **Sessions** shows `web` row → **Playback** shows I/O.
5. **Audit** contains `session.web_terminal.start` / `.end`.
6. Admin creates user and machine; user requests access; operator approves.
7. **Files** list/download against a connected agent.
8. **Security** MFA enroll/confirm; SSH key add.
9. After upgrade, UI version string matches `orion-belt-server --version` / `/api/v1/version`.

---

## 10. Traceability

| UI area | Primary OpenAPI tags |
|---------|----------------------|
| Login / Security | Auth, MFA, WebAuthn, SSH Keys |
| Terminal | Terminal, Sessions |
| Files | Files |
| Sessions / Audit | Sessions, Audit |
| Users / Machines / Agents | Users, Machines, Agents |
| Requests | Access Requests |
| Setup / Dashboard | Setup, Machines, Sessions |

---

## 11. Implementation notes

- **Source of truth for UI behavior:** `web/static/index.html` (embedded via `web/embed.go`).
- **No separate SPA build**; CDN loads xterm + FitAddon.
- **RBAC in UI** is navigation gating only; the API remains authoritative.
- Future UI RBAC / permission editors should extend this SRS rather than replace it silently.
