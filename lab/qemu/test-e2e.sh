#!/usr/bin/env bash
# Wait for gateway API + verify agents can be registered / connect.
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API="${ORION_API:-http://127.0.0.1:8080}"
SSH_KEY="${ORION_LAB_SSH_KEY:-$LAB/run/lab_id_ed25519}"

echo "==> Waiting for API at $API"
for i in $(seq 1 90); do
  if curl -fsS "$API/metrics" >/dev/null 2>&1 || curl -fsS "$API/api/v1/public/health" >/dev/null 2>&1; then
    echo "API is up"
    break
  fi
  # metrics may exist without /health — try TCP
  if (echo >/dev/tcp/127.0.0.1/8080) >/dev/null 2>&1; then
    echo "API port open"
    break
  fi
  sleep 5
  if [[ "$i" -eq 90 ]]; then
    echo "Timed out waiting for API" >&2
    exit 1
  fi
done

echo "==> Gateway SSH port"
for i in $(seq 1 60); do
  if (echo >/dev/tcp/127.0.0.1/2222) >/dev/null 2>&1; then
    echo "SSH gateway listening on :2222"
    break
  fi
  sleep 3
  if [[ "$i" -eq 60 ]]; then
    echo "Timed out waiting for :2222" >&2
    exit 1
  fi
done

echo "==> Agent SSH management ports (cloud-init progress)"
for port in 2201 2202 2203 2204; do
  if (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1; then
    echo "  :$port open"
  else
    echo "  :$port not yet open (agent still booting)"
  fi
done

echo "==> Collect agent public keys (when SSH is ready)"
collect_key() {
  local port="$1" user="$2" name="$3"
  if ! (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1; then
    echo "skip $name"
    return
  fi
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    -i "$SSH_KEY" -p "$port" "$user@127.0.0.1" \
    'cat /etc/orion-belt/agent_key.pub 2>/dev/null || true' \
    > "$LAB/run/${name}.pub" 2>/dev/null || true
  if [[ -s "$LAB/run/${name}.pub" ]]; then
    echo "  $name pubkey: $(cat "$LAB/run/${name}.pub")"
  fi
}

collect_key 2201 alpine agent-alpine
collect_key 2202 opensuse agent-opensuse
collect_key 2203 debian agent-debian
collect_key 2204 rocky agent-rocky

echo "==> Bootstrapping lab admin for /ui"
bash "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bootstrap-admin.sh"

echo "==> Connecting QEMU agents to the server"
bash "$LAB/connect-agents.sh"

cat <<EOF

Lab ready.
  UI:     http://127.0.0.1:8080/ui
  Admin:  make lab-bootstrap-admin / lab/credentials/admin_ed25519.pub
  Agents: make lab-qemu-connect-agents
  SSH:    ./lab/qemu/ssh.sh alpine
EOF
