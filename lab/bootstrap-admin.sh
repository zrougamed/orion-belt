#!/usr/bin/env bash
# Bootstrap a lab admin for the web UI (/ui).
# Auth is username + SSH public key (no password).
#
# Usage:
#   ./lab/bootstrap-admin.sh
#   ORION_API=http://127.0.0.1:8080 ./lab/bootstrap-admin.sh
#
# Env:
#   ORION_API           default http://127.0.0.1:8080
#   ORION_ADMIN_USER    default admin
#   ORION_ADMIN_EMAIL   default admin@lab.local
#   ORION_ADMIN_KEY_DIR default <repo>/lab/credentials
#   ORION_WAIT_SECS     default 300
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${ORION_API:-http://127.0.0.1:8080}"
USER_NAME="${ORION_ADMIN_USER:-admin}"
EMAIL="${ORION_ADMIN_EMAIL:-admin@lab.local}"
KEY_DIR="${ORION_ADMIN_KEY_DIR:-$ROOT/lab/credentials}"
KEY_PATH="${ORION_ADMIN_KEY_PATH:-$KEY_DIR/admin_ed25519}"
WAIT_SECS="${ORION_WAIT_SECS:-300}"
UI_URL="${ORION_UI_URL:-${API%/}/ui}"

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
need curl
need ssh-keygen
need python3

mkdir -p "$KEY_DIR"

echo "==> Waiting for API at $API (up to ${WAIT_SECS}s)"
deadline=$((SECONDS + WAIT_SECS))
ready=0
while (( SECONDS < deadline )); do
  if curl -fsS "$API/metrics" >/dev/null 2>&1; then
    ready=1
    break
  fi
  # Some builds may not expose /metrics yet — probe register endpoint shape
  code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/api/v1/public/register/client" \
    -H 'Content-Type: application/json' -d '{}' 2>/dev/null || true)"
  if [[ "$code" == "400" || "$code" == "409" || "$code" == "201" ]]; then
    ready=1
    break
  fi
  sleep 3
done
if [[ "$ready" -ne 1 ]]; then
  echo "API not reachable at $API — is the lab up? (make lab-qemu-up / make lab-compose-up)" >&2
  exit 1
fi
echo "API is up"

if [[ ! -f "$KEY_PATH" ]]; then
  echo "==> Generating admin SSH key: $KEY_PATH"
  ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "${USER_NAME}@orion-lab"
else
  echo "==> Reusing admin SSH key: $KEY_PATH"
fi
PUB="$(tr -d '\n' < "${KEY_PATH}.pub")"

echo "==> Registering admin user '$USER_NAME'"
payload="$(
  ORION_BOOT_USER="$USER_NAME" ORION_BOOT_EMAIL="$EMAIL" ORION_BOOT_PUB="$PUB" python3 - <<'PY'
import json, os
print(json.dumps({
  "username": os.environ["ORION_BOOT_USER"],
  "email": os.environ["ORION_BOOT_EMAIL"],
  "public_key": os.environ["ORION_BOOT_PUB"],
  "is_admin": True,
}))
PY
)"

tmp="$(mktemp)"
http_code="$(curl -sS -o "$tmp" -w '%{http_code}' -X POST "$API/api/v1/public/register/client" \
  -H 'Content-Type: application/json' \
  -d "$payload" || true)"

case "$http_code" in
  201)
    echo "Admin created (HTTP 201)"
    cat "$tmp"
    echo
    ;;
  409)
    echo "Admin already registered (HTTP 409) — OK, key above is what you use to sign in"
    ;;
  *)
    echo "Registration failed (HTTP ${http_code:-none}):" >&2
    cat "$tmp" >&2 || true
    echo >&2
    rm -f "$tmp"
    exit 1
    ;;
esac
rm -f "$tmp"

LOGIN_FILE="$KEY_DIR/UI-LOGIN.txt"
cat > "$LOGIN_FILE" <<EOF
Orion Belt lab — web UI admin login
===================================

URL:      $UI_URL
Username: $USER_NAME
SSH key:  paste the ONE-LINE public key below into "SSH public key"
TOTP:     leave empty (unless you enabled MFA)

Public key:
$PUB

Private key (keep local, for osh/ssh later):
$KEY_PATH

Re-run bootstrap:
  make lab-bootstrap-admin
EOF

cat <<EOF

╔══════════════════════════════════════════════════════════╗
║  Lab admin ready — open the UI and sign in               ║
╚══════════════════════════════════════════════════════════╝

  UI:       $UI_URL
  Username: $USER_NAME
  Pubkey:   ${KEY_PATH}.pub

  cat ${KEY_PATH}.pub

Details written to: $LOGIN_FILE
EOF
