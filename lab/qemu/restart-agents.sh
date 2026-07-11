#!/usr/bin/env bash
# Restart orion-belt-agent on each QEMU guest so it reconnects after registration.
# Uses POSIX sh on the guest; supports sudo and Alpine doas.
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

need ssh

restart_script() {
  cat <<'REMOTE'
set -e
if [ "$(id -u)" -eq 0 ]; then
  ASROOT=""
elif command -v sudo >/dev/null 2>&1; then
  ASROOT="sudo"
elif command -v doas >/dev/null 2>&1; then
  ASROOT="doas"
else
  echo "need root, sudo, or doas on guest" >&2
  exit 1
fi

run_root() {
  if [ -z "$ASROOT" ]; then
    "$@"
  else
    $ASROOT "$@"
  fi
}

run_root mkdir -p /etc/orion-belt /var/log

if [ ! -x /usr/bin/orion-belt-agent ]; then
  echo "orion-belt-agent missing on guest" >&2
  exit 1
fi
if [ ! -f /etc/orion-belt/agent_key ]; then
  run_root ssh-keygen -t ed25519 -f /etc/orion-belt/agent_key -N ""
fi
if [ ! -f /etc/orion-belt/agent.yaml ]; then
  echo "missing /etc/orion-belt/agent.yaml" >&2
  exit 1
fi

run_root pkill -f orion-belt-agent 2>/dev/null || true
sleep 1

# Start under root with redirects owned by root (Permission denied otherwise)
if [ -z "$ASROOT" ]; then
  nohup /usr/bin/orion-belt-agent -c /etc/orion-belt/agent.yaml >>/var/log/orion-agent.log 2>&1 &
else
  $ASROOT sh -c 'nohup /usr/bin/orion-belt-agent -c /etc/orion-belt/agent.yaml >>/var/log/orion-agent.log 2>&1 &'
fi
sleep 2

if run_root pgrep -f orion-belt-agent >/dev/null 2>&1; then
  echo "agent process running"
  run_root tail -n 12 /var/log/orion-agent.log 2>/dev/null || true
  exit 0
fi

echo "agent failed to start; last log:" >&2
run_root tail -n 40 /var/log/orion-agent.log 2>/dev/null || true
exit 1
REMOTE
}

restart_one() {
  local name="$1" port="$2" user="$3" distro="$4"
  if ! port_open "$port"; then
    echo "skip $name (:$port closed)"
    return 0
  fi
  if [[ ! -s "$RUN_DIR/${name}.pub" ]]; then
    echo "skip $name (no pubkey collected — guest not ready)"
    return 0
  fi
  echo "==> Restarting agent on $name"
  if ! restart_script | agent_ssh "$port" "$user" sh; then
    echo "  warn: restart command failed"
  fi
}

each_agent restart_one
echo "Restart pass complete."
