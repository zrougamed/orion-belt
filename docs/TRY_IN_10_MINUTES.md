# Try Orion Belt in 10 minutes

Goal: someone should go **gateway up → agent dials out → SSH works → session recorded → wow**.

This is a local lab path. For package installs and production hardening, use [SETUP.md](SETUP.md) and [DEPLOYMENT_HARDENING.md](DEPLOYMENT_HARDENING.md).

## Prerequisites

- Docker + Docker Compose
- `curl`, `openssl`, `ssh-keygen`
- ~10 minutes

## 1. Start the gateway (~2 min)

```bash
git clone https://github.com/orion-belt-dev/orion-belt.git
cd orion-belt
./scripts/docker-quickstart.sh
```

The script:

1. Writes `.env.server` (Postgres password + JWT secret) if missing
2. Starts Postgres + the Orion Belt server
3. Waits for `/health`
4. Creates an `admin` user and prints login material

You should see something like:

```text
== Ready ==
Web console: http://localhost:8080/ui
Log in with:
  username:   admin
  public key: ssh-ed25519 AAAA... orion-belt-admin
```

Keep `admin-key` (private) and `admin-key.pub` — both are git-ignored.

## 2. Sign in to the console (~1 min)

1. Open http://localhost:8080/ui
2. Username: `admin`
3. Public key: contents of `admin-key.pub`

There is no self-service signup; the first admin is bootstrapped from an SSH public key you control.

## 3. Register an agent (~2 min)

1. In the console, open **Add agent**
2. Pick a name (e.g. `lab-1`) — remember it
3. Generate / download the agent private key
4. Save it next to the repo as `./agent-key` and lock it down:

```bash
chmod 600 agent-key
```

Agents dial **out** to the gateway. You do not open inbound SSH on the target.

## 4. Run the agent (~2 min)

Same machine is fine for a lab:

```bash
cp .env.agent.example .env.agent
```

Edit `.env.agent`:

| Variable | Lab value |
| --- | --- |
| `ORION_AGENT_NAME` | Must match the name you registered (e.g. `lab-1`) |
| `ORION_SERVER_HOST` | How the agent container reaches the gateway — often `host.docker.internal` (Docker Desktop) or your host LAN IP |
| `ORION_SERVER_PORT` | `2222` (default) |

Then:

```bash
docker compose -f docker-compose.agent.yml --env-file .env.agent up -d
```

In the console, the agent should show as connected under **Agents**.

## 5. Grant access and SSH (~2 min)

1. Ensure your `admin` (or a user you create) can reach the machine — grant the agent / remote user as your role allows (console **Users** / permissions, or admin CLI)
2. Connect:
   - **Web terminal** from the console, or
   - CLI: `osh <agent-name>` (after configuring the client), or
   - OpenSSH: see [openssh-clients.md](openssh-clients.md)

Run a few commands in the session so there is something to replay.

## 6. Confirm recording (~1 min)

1. Open **Sessions** in the console
2. Find the session you just ran
3. **Playback** — or **live watch** if still active

Optional dashboard check (admin/operator/auditor): open **Dashboard → Access analytics** and verify rolling access volume, approval latency, and top targets update without generating a manual report.

That is the conversion moment: outbound agent, mediated SSH, audit trail — without exposing the target’s SSH port.

## Tear down

```bash
docker compose -f docker-compose.agent.yml --env-file .env.agent down
docker compose -f docker-compose.server.yml --env-file .env.server down
# optional: remove volumes if you want a clean slate
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Quickstart never becomes healthy | `docker compose -f docker-compose.server.yml --env-file .env.server logs server` |
| Agent won’t connect | `ORION_SERVER_HOST` / port `2222`; agent name matches registration; `agent-key` is the private key from **Add agent** |
| Can’t log into UI | Use the **public** key (`admin-key.pub`), not the private key |
| No recording | Confirm recording is enabled (default in the Docker server path) and the session actually ran through the gateway |

## Next steps

- Turn on MFA / WebAuthn — [SETUP.md](SETUP.md)
- Optional SSH CA — [SSH_CA.md](SSH_CA.md)
- Hardening before any real network — [DEPLOYMENT_HARDENING.md](DEPLOYMENT_HARDENING.md)
- Packages for durable installs — [PACKAGING.md](PACKAGING.md)

**Early operators:** if you deploy this and have feedback, open a [Discussion](https://github.com/orion-belt-dev/orion-belt/discussions) or an issue — we are looking for the first labs and small teams running v1.0.
