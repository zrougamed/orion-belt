#!/usr/bin/env bash
# Restart QEMU lab VMs in place (reuse existing disks + seed ISOs).
# Does not wipe disks, rebuild packages, or re-run cloud-init provisioning.
#
# Usage:
#   ./lab/qemu/restart.sh                 # all VMs that have a disk under run/
#   ./lab/qemu/restart.sh server
#   ./lab/qemu/restart.sh alpine debian
#   ./lab/qemu/restart.sh agent-rocky
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$LAB/run"

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
need qemu-system-x86_64

# name|mem|cpus|hostfwd
vm_spec() {
  case "$1" in
    server)
      echo "1536|2|hostfwd=tcp::2222-:2222,hostfwd=tcp::8080-:8080,hostfwd=tcp::2200-:22"
      ;;
    agent-alpine)
      echo "768|1|hostfwd=tcp::2201-:22"
      ;;
    agent-opensuse)
      echo "768|1|hostfwd=tcp::2202-:22"
      ;;
    agent-debian)
      echo "768|1|hostfwd=tcp::2203-:22"
      ;;
    agent-rocky)
      echo "768|1|hostfwd=tcp::2204-:22"
      ;;
    *)
      return 1
      ;;
  esac
}

normalize_name() {
  case "$1" in
    server|ubuntu) echo server ;;
    alpine|agent-alpine) echo agent-alpine ;;
    opensuse|suse|agent-opensuse) echo agent-opensuse ;;
    debian|agent-debian) echo agent-debian ;;
    rocky|agent-rocky) echo agent-rocky ;;
    *)
      echo "unknown VM: $1 (use server|alpine|opensuse|debian|rocky)" >&2
      return 1
      ;;
  esac
}

stop_vm() {
  local name="$1"
  local pidfile="$RUN/${name}.pid"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      echo "stopped $name (pid $pid)"
    else
      echo "$name pidfile stale — clearing"
    fi
    rm -f "$pidfile"
  else
    # Best-effort leftover by qemu -name
    pkill -f "qemu-system-x86_64 -name ${name}( |$)" 2>/dev/null || true
    echo "$name was not running"
  fi
}

start_vm() {
  local name="$1"
  local disk="$RUN/${name}.qcow2"
  local seed="$RUN/${name}-seed.iso"
  local pidfile="$RUN/${name}.pid"
  local log="$RUN/logs/${name}.log"
  local spec mem cpus hostfwd

  [[ -f "$disk" ]] || { echo "skip $name (no disk at $disk — boot with up.sh first)" >&2; return 1; }
  [[ -f "$seed" ]] || { echo "skip $name (no seed ISO at $seed)" >&2; return 1; }

  if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    echo "VM $name already running"
    return 0
  fi

  spec="$(vm_spec "$name")"
  IFS='|' read -r mem cpus hostfwd <<<"$spec"
  mkdir -p "$RUN/logs"

  # shellcheck disable=SC2086
  qemu-system-x86_64 \
    -name "$name" \
    -machine pc,accel=kvm:tcg \
    -cpu max \
    -m "$mem" \
    -smp "$cpus" \
    -drive file="$disk",if=virtio,format=qcow2 \
    -drive file="$seed",if=virtio,format=raw \
    -netdev user,id=net0,${hostfwd} \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial file:"$log" \
    -daemonize \
    -pidfile "$pidfile"

  echo "restarted $name (pid $(cat "$pidfile")) — serial log: $log"
}

resolve_targets() {
  local arg name
  if [[ "$#" -eq 0 ]]; then
    for name in server agent-alpine agent-opensuse agent-debian agent-rocky; do
      [[ -f "$RUN/${name}.qcow2" ]] && echo "$name"
    done
    return
  fi
  for arg in "$@"; do
    normalize_name "$arg"
  done
}

mapfile -t TARGETS < <(resolve_targets "$@")
if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  echo "No VM disks found under $RUN — run make lab-qemu-up first." >&2
  exit 1
fi

echo "==> Restarting QEMU VMs (disks retained): ${TARGETS[*]}"
for name in "${TARGETS[@]}"; do
  stop_vm "$name"
done
# Brief pause so ports are released
sleep 1
fail=0
for name in "${TARGETS[@]}"; do
  start_vm "$name" || fail=1
done

if [[ "$fail" -ne 0 ]]; then
  echo "Some VMs failed to restart." >&2
  exit 1
fi

echo "Done. Mgmt SSH: ./lab/qemu/ssh.sh server|alpine|opensuse|debian|rocky"
