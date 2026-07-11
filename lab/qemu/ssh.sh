#!/usr/bin/env bash
# SSH helper into a QEMU lab agent or the server VM.
#
# Usage:
#   ./lab/qemu/ssh.sh server
#   ./lab/qemu/ssh.sh alpine
#   ./lab/qemu/ssh.sh opensuse -- 'cat /var/log/orion-agent.log'
#   ./lab/qemu/ssh.sh debian
#   ./lab/qemu/ssh.sh rocky
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

need ssh

target="${1:-}"
[[ -n "$target" ]] || {
  echo "Usage: $0 <server|alpine|opensuse|debian|rocky> [-- remote-cmd...]" >&2
  exit 1
}
shift || true
# optional -- before remote command
if [[ "${1:-}" == "--" ]]; then shift; fi

case "$target" in
  server|ubuntu)
    port=2200; user=ubuntu ;;
  alpine|agent-alpine)
    port=2201; user=alpine ;;
  opensuse|suse|agent-opensuse)
    port=2202; user=opensuse ;;
  debian|agent-debian)
    port=2203; user=debian ;;
  rocky|agent-rocky)
    port=2204; user=rocky ;;
  *)
    echo "unknown target: $target" >&2
    exit 1
    ;;
esac

if [[ "$#" -gt 0 ]]; then
  agent_ssh "$port" "$user" "$@"
else
  agent_ssh "$port" "$user"
fi
