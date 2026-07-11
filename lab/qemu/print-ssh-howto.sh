#!/usr/bin/env bash
# Print how to use the QEMU lab gateway from this host via OpenSSH / osh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRED_DIR="${ORION_ADMIN_KEY_DIR:-$ROOT/lab/credentials}"
GW_HOST="${ORION_GW_HOST:-127.0.0.1}"
GW_PORT="${ORION_GW_PORT:-2222}"
UI="${ORION_UI_URL:-http://127.0.0.1:8080/ui}"

ALICE_KEY="$CRED_DIR/alice_ed25519"
ADMIN_KEY="$CRED_DIR/admin_ed25519"
BOB_KEY="$CRED_DIR/bob_ed25519"

cat <<EOF

════════════════════════════════════════════════════════════
  Credentials & SSH usage (this host → Orion gateway)
════════════════════════════════════════════════════════════

UI:  $UI
     Username + paste the matching *.pub file (no password).

Admin pubkey:
  cat ${ADMIN_KEY}.pub

Demo users summary:
  cat $CRED_DIR/USERS.txt 2>/dev/null || true
  ls -1 $CRED_DIR/*.pub 2>/dev/null || true

── OpenSSH through the gateway (port $GW_PORT) ──

# Alice → Alpine agent (shell as root on the agent by default)
ssh -i $ALICE_KEY -p $GW_PORT \\
  alice+agent-alpine@${GW_HOST}

# Alice → Alpine as remote user 'alpine' (if that account exists on guest)
ssh -i $ALICE_KEY -p $GW_PORT \\
  'alice+alpine%agent-alpine@${GW_HOST}'

# Bob → Debian only (granted ssh on agent-debian)
ssh -i $BOB_KEY -p $GW_PORT \\
  bob+agent-debian@${GW_HOST}

# Admin can reach any registered machine
ssh -i $ADMIN_KEY -p $GW_PORT \\
  admin+agent-alpine@${GW_HOST}

── Optional ~/.ssh/config snippet ──

Host orion-gw
  HostName $GW_HOST
  Port $GW_PORT
  IdentityFile $ALICE_KEY
  IdentitiesOnly yes

Host alpine.orion
  HostName $GW_HOST
  Port $GW_PORT
  User alice+agent-alpine
  IdentityFile $ALICE_KEY
  IdentitiesOnly yes
  RequestTTY force

Then:  ssh alpine.orion

── osh (if built) ──

  ./bin/osh -i $ALICE_KEY agent-alpine
  # or with config pointing at $GW_HOST:$GW_PORT

── Management SSH into VMs (not through Orion) ──

  ./lab/qemu/ssh.sh server
  ./lab/qemu/ssh.sh alpine

════════════════════════════════════════════════════════════
EOF
