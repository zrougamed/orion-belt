#!/usr/bin/env bash
# Shared helpers for QEMU lab agent scripts.
# shellcheck disable=SC2034

LAB_QEMU="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "$LAB_QEMU/.." && pwd)"
ROOT="$(cd "$LAB_ROOT/.." && pwd)"

API="${ORION_API:-http://127.0.0.1:8080}"
SSH_KEY="${ORION_LAB_SSH_KEY:-$LAB_QEMU/run/lab_id_ed25519}"
AGENTS_CONF="${ORION_AGENTS_CONF:-$LAB_QEMU/agents.conf}"
RUN_DIR="${ORION_LAB_RUN:-$LAB_QEMU/run}"

ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -o LogLevel=ERROR -o BatchMode=yes)

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }

wait_api() {
  local secs="${1:-180}"
  local deadline=$((SECONDS + secs))
  echo "==> Waiting for API at $API"
  while (( SECONDS < deadline )); do
    if curl -fsS "$API/metrics" >/dev/null 2>&1; then
      echo "API is up"
      return 0
    fi
    sleep 3
  done
  echo "API not reachable at $API" >&2
  return 1
}

# Iterate agents.conf → name port user distro
each_agent() {
  local line name port user distro
  [[ -f "$AGENTS_CONF" ]] || { echo "missing $AGENTS_CONF" >&2; return 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    IFS='|' read -r name port user distro <<<"$line"
    "$@" "$name" "$port" "$user" "$distro"
  done < "$AGENTS_CONF"
}

port_open() {
  local port="$1"
  (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
}

agent_ssh() {
  local port="$1" user="$2"
  shift 2
  ssh "${ssh_opts[@]}" -i "$SSH_KEY" -p "$port" "${user}@127.0.0.1" "$@"
}
