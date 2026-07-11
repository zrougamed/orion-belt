#!/usr/bin/env bash
# Collect agent SSH public keys from running QEMU VMs into lab/qemu/run/*.pub
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

need ssh
mkdir -p "$RUN_DIR"

# Guest privilege helper: prefer sudo, fall back to Alpine doas.
fetch_pubkey_script() {
  cat <<'REMOTE'
set -e
if [ "$(id -u)" -eq 0 ]; then
  ASROOT=""
elif command -v sudo >/dev/null 2>&1; then
  ASROOT="sudo"
elif command -v doas >/dev/null 2>&1; then
  ASROOT="doas"
else
  echo "need root, sudo, or doas" >&2
  exit 1
fi
$ASROOT mkdir -p /etc/orion-belt
if [ ! -f /etc/orion-belt/agent_key ]; then
  $ASROOT ssh-keygen -t ed25519 -f /etc/orion-belt/agent_key -N "" -q
fi
$ASROOT cat /etc/orion-belt/agent_key.pub
REMOTE
}

collect_one() {
  local name="$1" port="$2" user="$3" distro="$4"
  local out="$RUN_DIR/${name}.pub"
  if ! port_open "$port"; then
    echo "skip $name (:$port not open — still booting?)"
    return 0
  fi
  echo "==> $name ($user@127.0.0.1:$port)"

  if ! fetch_pubkey_script | agent_ssh "$port" "$user" sh >"$out" 2>/dev/null; then
    echo "  ssh failed (cloud-init / sshd not ready?)"
    rm -f "$out"
    return 0
  fi

  if [[ -s "$out" ]]; then
    grep -E '^ssh-|^ecdsa-|^sk-' "$out" | head -1 >"${out}.tmp" && mv "${out}.tmp" "$out"
  fi

  if [[ -s "$out" ]]; then
    echo "  saved $out"
    echo "  $(cat "$out")"
  else
    echo "  still no pubkey"
    rm -f "$out"
  fi
}

echo "Collecting agent public keys (SSH key: $SSH_KEY)"
each_agent collect_one
echo "Done. Pubkeys under $RUN_DIR/"
