#!/usr/bin/env bash
# Tear down the QEMU lab and wipe local state.
# Default: stop VMs + delete run overlays, cloud images, and lab credentials.
#
# Opt-outs (only if you need them):
#   KEEP_IMAGES=1   keep lab/qemu/images/
#   KEEP_CREDS=1    keep lab/credentials/
#   KEEP_DIST=1     keep dist/ package mirror binaries
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$LAB/../.." && pwd)"
RUN="$LAB/run"
IMG="$LAB/images"
CREDS="$ROOT/lab/credentials"

echo "==> Stopping QEMU lab"
bash "$LAB/down.sh" || true

# Kill leftover package HTTP server if still bound
if [[ -f "$RUN/pkg-server.pid" ]]; then
  pid="$(cat "$RUN/pkg-server.pid" 2>/dev/null || true)"
  if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
fi
pkill -f "python3 -m http.server .*${ROOT}/dist" 2>/dev/null || true

echo "==> Removing run state ($RUN)"
rm -rf "$RUN"
mkdir -p "$RUN/logs"

if [[ "${KEEP_IMAGES:-0}" != "1" ]]; then
  echo "==> Removing cloud images ($IMG)"
  rm -rf "$IMG"
  mkdir -p "$IMG"
else
  echo "==> Keeping cloud images (KEEP_IMAGES=1)"
fi

if [[ "${KEEP_CREDS:-0}" != "1" ]]; then
  echo "==> Removing lab credentials ($CREDS)"
  rm -rf "$CREDS"
else
  echo "==> Keeping lab credentials (KEEP_CREDS=1)"
fi

if [[ "${KEEP_DIST:-0}" != "1" ]]; then
  # Only clear lab-built binaries; leave gitignored dist empty for next start
  if [[ -d "$ROOT/dist" ]]; then
    echo "==> Clearing dist/ mirror"
    rm -rf "$ROOT/dist"
  fi
fi

echo "QEMU lab cleaned."
