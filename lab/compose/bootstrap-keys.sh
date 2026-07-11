#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DIR/agent-keys"
if [[ ! -f "$DIR/agent-keys/agent_key" ]]; then
  ssh-keygen -t ed25519 -f "$DIR/agent-keys/agent_key" -N "" -C "orion-lab-agent"
  echo "Generated $DIR/agent-keys/agent_key"
  echo "Register the public key with the server after first boot:"
  echo "  cat $DIR/agent-keys/agent_key.pub"
fi
