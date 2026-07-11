#!/usr/bin/env bash
set -euo pipefail
LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$LAB/run"

stop_pidfile() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local pid
  pid="$(cat "$f")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
    echo "stopped pid $pid ($f)"
  fi
  rm -f "$f"
}

shopt -s nullglob
for f in "$RUN"/*.pid; do
  stop_pidfile "$f"
done

# Leftover qemu by name
pkill -f 'qemu-system-x86_64 -name (server|agent-)' 2>/dev/null || true

echo "QEMU lab stopped. Disks retained under $RUN (delete to reset)."
