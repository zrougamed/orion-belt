# Deployment hardening guide

Checklist for production Orion Belt gateways (**v0.9.0+**). Pair with [SETUP.md](SETUP.md) and [OBSERVABILITY.md](OBSERVABILITY.md).

## Network

- [ ] Bind SSH (`server.ssh_port`, default 2222) and HTTP API only on management / internal interfaces where possible; put a reverse proxy in front of HTTP `:8080` for TLS termination.
- [ ] Do **not** expose PostgreSQL beyond the gateway hosts; use private network + TLS or a managed DB with IP allowlists.
- [ ] Restrict who can dial the bastion: VPN, zero-trust, or firewall ACLs from operator networks.
- [ ] Agents dial **out** to the gateway — keep inbound agent ports closed on targets.

## TLS and cookies

- [ ] Terminate TLS at the proxy with a trusted certificate; set WebAuthn RP ID / origins to the public hostname.
- [ ] Serve the console and API over HTTPS only in production so `session_token` cookies and WebAuthn work securely.
- [ ] Prefer short session TTLs; require MFA when `auth.mfa_required` or when password login is enabled.

## Secrets and config

- [ ] Keep `config/server.yaml` mode `0600` owned by the service user; never commit real secrets.
- [ ] Put `recording.encryption_key`, DB passwords, JWT/signing material, and plugin webhooks in a secrets manager or systemd `EnvironmentFile` with restricted permissions.
- [ ] Rotate plugin webhook URLs and API keys after staff changes; revoke unused API keys from Security → API keys.
- [ ] If SSH CA is enabled, protect CA private keys (`ssh_ca.master_key` / encrypted rows) as crown jewels — same care as a HashiCorp Vault root.

## Authn / authz

- [ ] Disable unused login paths; enroll admins with WebAuthn or TOTP before going live.
- [ ] Prefer challenge-response / key login for CLI; use password+TOTP only when needed for break-glass or browser users.
- [ ] Keep OpenFGA (or ReBAC grants) aligned with least privilege; review Permissions “All grants” periodically.
- [ ] Limit `admin` / `operator` roles; auditors should be read-mostly.

## Recording and retention

- [ ] Enable `recording.enabled` and set `retention_days` to your compliance window.
- [ ] Use `recording.compression: gzip` (default) to reduce disk; set `encryption_key` for at-rest cast files.
- [ ] Back up the recording volume separately from the database; test playback after restore.

## Runtime

- [ ] Run the gateway and agents as non-root where possible; agents that need privilege drop still start with capability to spawn sessions.
- [ ] Use systemd `ProtectSystem=`, `PrivateTmp=`, and capability bounding sets from packaged unit files; tighten further if you vendor your own units.
- [ ] Scrape `/metrics` and ship JSON logs; load the sample alerts in [OBSERVABILITY.md](OBSERVABILITY.md).
- [ ] Keep images/packages updated; subscribe to release notes for security fixes.

## Operational drills

- [ ] Practice revoke of a compromised user (disable user, revoke keys/API keys, expire grants).
- [ ] Practice agent disconnect / reinstall via install script.
- [ ] Confirm audit logs capture login, grant, approve/reject, and session start/stop.
