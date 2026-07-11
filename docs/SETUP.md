# First-run setup

After installing the `orion-belt` package, follow this path.

## 1. Configure the server

```bash
sudoedit /etc/orion-belt/server.yaml
```

Set at least:

- `database.connection_string` — Postgres DSN
- `auth.jwt_secret` — long random string (not the example value)

```bash
sudo systemctl enable --now orion-belt-server
```

UI: `http://<host>:8080/ui`

## 2. Run the setup wizard

```bash
sudo -u orionbelt orion-belt-server -c /etc/orion-belt/server.yaml setup
```

Creates the first **admin** (if missing) and prints agent/user guidance.

Non-interactive:

```bash
export ORION_SETUP_ADMIN_NAME=admin
export ORION_SETUP_ADMIN_EMAIL=admin@example.com
export ORION_SETUP_ADMIN_KEY_FILE=/path/to/admin.pub
orion-belt-server -c /etc/orion-belt/server.yaml setup
```

## 3. Add agents

On each target host:

1. Install `orion-belt-agent` (see [PACKAGING.md](PACKAGING.md) for apt/dnf/apk/Arch).
2. Edit `/etc/orion-belt/agent.yaml` — gateway host and port **2222**.
3. `systemctl enable --now orion-belt-agent`
4. Register the agent (UI **Agents**, or `POST /api/v1/public/register/agent`).

## 4. Users and grants

- UI **Users** — create operators / auditors / users
- Grant machine access with `remote_users` (e.g. `root`)
- CLI:

```bash
orion-belt-server user create --name alice --email a@x --key "$(cat alice.pub)"
orion-belt-server permission grant --user alice --machine web-01 --type both --remote-users root
```

## 5. Connect (everything is recorded)

OpenSSH through the gateway:

```bash
ssh -i alice.pem -p 2222 alice+web-01@gateway-host
```

Web **Terminal** in the UI also creates auditable sessions with recordings.

Direct SSH to an agent host **bypasses** Orion (no recording). Point users at the gateway.

## UI checklist

Admins/operators see **Setup guide** in the nav and a dashboard banner until agents are connected.
