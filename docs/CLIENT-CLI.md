# Client CLI flags (osh / ocp / oadmin)

Shared persistent flags (all three tools):

| Flag | Env | Purpose |
|------|-----|---------|
| `-c, --config` | `ORION_CONFIG` | Client YAML path (default `~/.orion-belt/client.yaml`) |
| `-u, --user` | `ORION_USER` | Gateway username |
| `--api-endpoint` | `ORION_API_ENDPOINT` | HTTP API base (no trailing `/api`) |
| `-i, --identity` | — | Private key path (overrides `auth.key_file`) |
| `-v, --verbose` | — | Debug logging |
| `--json` | — | JSON output where implemented |
| `--timeout` | — | HTTP / dial timeout (default 30s) |

SSH clients (`osh`, `ocp`) additionally:

| Flag | Purpose |
|------|---------|
| `--proxy` | Gateway SSH host (overrides `server.host`) |
| `--proxy-port` | Gateway SSH port |
| `--insecure` / `--no-host-key-check` | Skip host-key verify (`strict_host_key_checking=no`) |

### First run (no config yet)

If `~/.orion-belt/client.yaml` (or `-c` path) is missing, `osh` / `ocp` / `oadmin`
start an interactive wizard: host, SSH port, API URL, username, key path. It
checks that the private key parses and that the API answers (`/api/v1/version`
or `/health`). If the API is down you can abort or save anyway.

### `osh login`

```bash
osh login                 # SSH key auth → open browser with one-time code
osh login --code          # print code + URL instead (CI / headless)
osh login --password      # prompt for password + TOTP, then open browser
osh login --password --code
```

Password login requires an account password and enrolled TOTP (set once in the
console under Security, or via the post-login setup gate). For hardware keys on
SSH itself, use an `sk-*` identity (`-i ~/.ssh/id_ed25519_sk`); browser WebAuthn
stays a console login method.

### Examples

```bash
osh -c ./client.yaml -u admin --api-endpoint http://localhost:8080 login
osh -u alice login --password
osh -u alice --proxy bastion.example.com --proxy-port 2222 -i ~/.ssh/alice web-01
ocp -u alice --insecure ./file web-01:/tmp/file
oadmin -u admin --api-endpoint http://localhost:8080 requests list --json
```


