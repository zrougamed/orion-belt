#!/bin/sh
set -eu

SERVER="${ORION_SERVER:-server}"
PORT="${ORION_PORT:-2222}"
NAME="${ORION_AGENT_NAME:-lab-agent}"
KEY_FILE="${ORION_KEY_FILE:-/keys/agent_key}"
CFG=/tmp/agent.yaml

if [ ! -f "$KEY_FILE" ]; then
  echo "missing agent key at $KEY_FILE — run lab/compose/bootstrap-keys.sh first" >&2
  # Generate ephemeral key so the container still starts for debugging
  mkdir -p /tmp/keys
  KEY_FILE=/tmp/keys/agent_key
  if command -v ssh-keygen >/dev/null 2>&1; then
    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -q
  else
    echo "ssh-keygen not available and no key provided" >&2
    sleep infinity
  fi
fi

cat > "$CFG" <<EOF
server:
  host: "${SERVER}"
  port: ${PORT}

agent:
  name: "${NAME}"
  tags:
    environment: lab
    role: agent

auth:
  key_file: "${KEY_FILE}"
  known_hosts: "/tmp/known_hosts"
  strict_host_key_checking: "no"
EOF

exec /usr/bin/orion-belt-agent -c "$CFG"
