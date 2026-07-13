#!/usr/bin/env bash
# Orion Belt — one-command Docker quick start.
#
# Brings up the server stack, generates the secrets it needs, and bootstraps
# the first admin user — the pieces docker-compose.server.yml deliberately
# doesn't automate on its own (secrets shouldn't be silently invented by a
# compose file, and admin bootstrap is a security-sensitive one-time step).
#
# Usage: ./scripts/docker-quickstart.sh
# Safe to re-run: skips any step that's already done.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

COMPOSE=(docker compose -f docker-compose.server.yml --env-file .env.server)
API_PORT="${ORION_API_PORT:-8080}"

echo "== Orion Belt Docker quick start =="

# 1. Secrets: generate .env.server if it doesn't exist yet.
if [ ! -f .env.server ]; then
  echo "-> generating .env.server (Postgres password + JWT secret)"
  {
    echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
    echo "ORION_JWT_SECRET=$(openssl rand -hex 32)"
  } > .env.server
else
  echo "-> .env.server already exists, reusing it"
fi

# 2. Bring the stack up.
echo "-> starting Postgres + server (docker compose up -d --build)"
"${COMPOSE[@]}" up -d --build

# 3. Wait for the API to answer.
echo -n "-> waiting for the server to become healthy"
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 2
done
if ! curl -sf "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then
  echo
  echo "Server didn't become healthy in time. Check: ${COMPOSE[*]} logs server" >&2
  exit 1
fi

# 4. Admin keypair: generate one locally if missing.
if [ ! -f admin-key ]; then
  echo "-> generating admin-key (ed25519 keypair for the first admin login)"
  ssh-keygen -t ed25519 -f admin-key -N "" -C "orion-belt-admin" -q
fi

# 5. Bootstrap the first admin, if one doesn't exist yet. The setup command is
# idempotent about this (it detects an existing admin and no-ops), so it's
# safe to run every time this script runs.
echo "-> ensuring an admin user exists"
"${COMPOSE[@]}" exec -T \
  -e ORION_SETUP_ADMIN_NAME=admin \
  -e ORION_SETUP_ADMIN_EMAIL=admin@localhost \
  -e ORION_SETUP_ADMIN_KEY="$(cat admin-key.pub)" \
  server /app/orion-belt-server -c /etc/orion-belt/config.generated.yaml setup < /dev/null

echo
echo "== Ready =="
echo "Web console: http://localhost:${API_PORT}/ui"
echo "Log in with:"
echo "  username:   admin"
echo "  public key: $(cat admin-key.pub)"
echo
echo "(admin-key is your private key — keep it, it's how the CLI/API"
echo " authenticate as this user too. It's already git-ignored.)"
echo
echo "Next: register a machine (web console -> Add agent), then see"
echo "docker-compose.agent.yml to run an agent on it."
