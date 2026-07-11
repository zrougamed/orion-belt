#!/usr/bin/env bash
# End-to-end: collect keys → register agents on the server → restart agents.
#
# Usage:
#   make lab-qemu-connect-agents
#   ./lab/qemu/connect-agents.sh
#   ./lab/qemu/connect-agents.sh alpine debian   # only some guests
set -euo pipefail

LAB_QEMU="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$LAB_QEMU/lib.sh"

FILTERS=("$@")
match_filter() {
  local name="$1" distro="$2"
  [[ "${#FILTERS[@]}" -eq 0 ]] && return 0
  local f
  for f in "${FILTERS[@]}"; do
    [[ "$name" == *"$f"* || "$distro" == "$f" || "agent-$f" == "$name" ]] && return 0
  done
  return 1
}

# Temporarily narrow agents.conf via filter by exporting a subset file
if [[ "${#FILTERS[@]}" -gt 0 ]]; then
  tmp="$(mktemp)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    IFS='|' read -r name port user distro <<<"$line"
    if match_filter "$name" "$distro"; then
      echo "$line" >>"$tmp"
    fi
  done < "$AGENTS_CONF"
  if [[ ! -s "$tmp" ]]; then
    echo "no agents matched: ${FILTERS[*]}" >&2
    rm -f "$tmp"
    exit 1
  fi
  export ORION_AGENTS_CONF="$tmp"
  # re-source so AGENTS_CONF updates — set explicitly
  AGENTS_CONF="$tmp"
  trap 'rm -f "$tmp"' EXIT
  echo "Connecting subset:"
  cat "$tmp"
fi

echo "╔══════════════════════════════════════════════╗"
echo "║  QEMU lab → connect agents to Orion server   ║"
echo "╚══════════════════════════════════════════════╝"
echo "API: $API"

bash "$LAB_QEMU/collect-agent-keys.sh"
# re-export conf for child scripts when filtered
if [[ -n "${ORION_AGENTS_CONF:-}" ]]; then
  ORION_AGENTS_CONF="$AGENTS_CONF" bash "$LAB_QEMU/register-agents.sh"
  ORION_AGENTS_CONF="$AGENTS_CONF" bash "$LAB_QEMU/restart-agents.sh"
else
  bash "$LAB_QEMU/register-agents.sh"
  bash "$LAB_QEMU/restart-agents.sh"
fi

echo
echo "Next:"
echo "  1) UI:  http://127.0.0.1:8080/ui  (make lab-bootstrap-admin if needed)"
echo "  2) List machines after login, or:"
echo "       curl -sS $API/api/v1/machines -H \"Authorization: Bearer \$TOKEN\""
echo "  3) SSH a guest:  ./lab/qemu/ssh.sh alpine"
echo "  4) Agent logs:   ./lab/qemu/ssh.sh alpine -- 'sudo tail -50 /var/log/orion-agent.log'"
