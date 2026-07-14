# Deployment hardening

Things to tighten before you put a gateway on a real network. Useful alongside [SETUP.md](SETUP.md) and [OBSERVABILITY.md](OBSERVABILITY.md). We also expect this list to be walked before tagging [v1.0](V1_RELEASE_CRITERIA.md).

## Network

- [ ] Prefer binding SSH (`server.ssh_port`, usually 2222) and HTTP to interfaces that aren’t the whole internet; put TLS in front of `:8080`.
- [ ] Don’t expose Postgres to the world — private net, TLS, or a managed DB with IP allows.
- [ ] Limit who can reach the bastion (VPN, ztna, firewall from your ops nets).
- [ ] Agents connect **out** to the gateway — no inbound agent ports on targets.

## TLS and cookies

- [ ] Real cert on the reverse proxy; WebAuthn RP ID / origins match the public hostname.
- [ ] HTTPS for the console and API in real deploys (cookies + WebAuthn).
- [ ] Short session TTLs; turn on `auth.mfa_required` or use password login only when you know what you’re doing.

## Secrets and config

- [ ] `server.yaml` mode `0600`, owned by the service user; never commit live secrets.
- [ ] Put encryption keys, DB passwords, JWT material, webhook URLs in a secret store or a locked-down `EnvironmentFile`.
- [ ] Rotate webhooks / API keys when people leave; revoke unused keys in Security → API keys.
- [ ] Treat SSH CA private material like the keys to the kingdom.

## Auth

- [ ] Turn off login paths you don’t need; enroll admins with WebAuthn or TOTP before go-live.
- [ ] Prefer key / challenge login for CLI; password+TOTP for break-glass / browser if you must.
- [ ] Keep grants tight; glance at Permissions → All grants now and then.
- [ ] Few `admin` / `operator` accounts; auditors stay read-mostly.

## Recording

- [ ] `recording.enabled` on, `retention_days` set to whatever your policy is.
- [ ] `compression: gzip` is fine; set `encryption_key` if casts can’t sit plaintext on disk.
- [ ] Back up the recording volume separately from the DB; test playback after a restore.

## Runtime

- [ ] Non-root where you can; agents may still need privilege to drop into session users.
- [ ] Use the packaged unit hardening (`ProtectSystem=`, etc.) or something equivalent.
- [ ] Scrape `/metrics`, ship JSON logs; alerts in [OBSERVABILITY.md](OBSERVABILITY.md) are a starting point.
- [ ] Keep packages updated.

## Drills

- [ ] Revoke a compromised user (disable, yank keys/API keys, expire grants).
- [ ] Disconnect / reinstall an agent with the install script.
- [ ] Confirm audit shows login, grant, approve/reject, session start/stop.
