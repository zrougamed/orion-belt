#!/usr/bin/env bash
# Full QEMU lab bring-up:
#   1) clean (default)  2) boot server+agents  3) admin  4) connect agents
#   5) seed RBAC users  6) print SSH howto + credentials
#
#   ./lab/qemu/start.sh
#   SKIP_CLEAN=1 ./lab/qemu/start.sh          # keep existing disks/images
#   KEEP_IMAGES=1 ./lab/qemu/start.sh         # clean but re-use downloaded qcow2
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$LAB/../.." && pwd)"
CRED_DIR="${ORION_ADMIN_KEY_DIR:-$ROOT/lab/credentials}"
API="${ORION_API:-http://127.0.0.1:8080}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Orion Belt QEMU lab — clean start                   ║"
echo "╚══════════════════════════════════════════════════════╝"

if [[ "${SKIP_CLEAN:-0}" != "1" ]]; then
  # Preserve KEEP_* for clean.sh
  bash "$LAB/clean.sh"
else
  echo "==> SKIP_CLEAN=1 — not wiping prior state"
  bash "$LAB/down.sh" || true
fi

echo
echo "==> [1/5] Boot server + agent VMs"
bash "$LAB/up.sh"

echo
echo "==> Waiting for gateway API (cloud-init can take several minutes)"
deadline=$((SECONDS + ${ORION_WAIT_SECS:-600}))
until curl -fsS "$API/metrics" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "API did not become ready at $API" >&2
    echo "Check: ./lab/qemu/ssh.sh server — and /var/log/orion-belt/server.log" >&2
    exit 1
  fi
  sleep 5
done
echo "API is up"

echo
echo "==> [2/5] Bootstrap admin"
bash "$ROOT/lab/bootstrap-admin.sh"

echo
echo "==> [3/5] Connect agents"
bash "$LAB/connect-agents.sh"

echo
echo "==> [4/5] Seed users (roles + grants)"
bash "$LAB/seed-users.sh"

echo
echo "==> [5/5] SSH from this host"
bash "$LAB/print-ssh-howto.sh"

echo
echo "Lab start complete."
