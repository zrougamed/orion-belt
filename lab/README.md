# Multi-distro test lab

Two ways to run the server and attach agents across current Linux releases:

| Lab | When to use | Command |
|-----|-------------|---------|
| **Docker Compose** (`lab/compose`) | Fast CI / laptop smoke test | `make lab-compose-up` |
| **QEMU cloud images** (`lab/qemu`) | Near-native packages + cloud-init | `make lab-qemu-up` |

## Current OS images (latest pins)

### Docker Compose agents

| Service | Base image |
|---------|------------|
| `agent-ubuntu` | `ubuntu:25.04` |
| `agent-alpine` | `alpine:3.22` |
| `agent-suse` | `opensuse/leap:16.0` |
| `agent-debian` | `debian:trixie-slim` (Debian 13) |
| `agent-rocky` | `rockylinux/rockylinux:10` |

### QEMU cloud images (`lab/qemu/distros.yaml`)

| Guest | Image | Notes |
|-------|-------|-------|
| Server | Ubuntu 24.04 LTS minimal **daily/current** | freshest noble builds |
| Agent | Alpine **3.22.x** nocloud (auto-resolved to newest patch) | `download-images.sh` picks latest |
| Agent | openSUSE **Tumbleweed** Minimal VM Cloud | rolling |
| Agent | Debian **13 (trixie)** genericcloud | `.../trixie/latest/...` |
| Agent | Rocky Linux **9** GenericCloud `.latest` | official Rocky cloud |

Refresh cached downloads:

```bash
ORION_REFRESH_IMAGES=1 make lab-qemu-images
```

## Docker Compose lab (no QEMU)

```bash
./lab/compose/bootstrap-keys.sh
make lab-compose-up
# Gateway: localhost:2222  API: localhost:8080
docker compose -f lab/compose/docker-compose.yml ps
make lab-compose-down
```

Register `lab/compose/agent-keys/agent_key.pub` with the server before agents authenticate.

## QEMU lab

### Host dependencies

```bash
# Debian/Ubuntu host
sudo apt install qemu-system-x86 qemu-utils cloud-image-utils genisoimage openssh-client curl

# Fedora
sudo dnf install qemu-system-x86 qemu-img cloud-utils genisoimage openssh-clients curl
```

KVM is used when `/dev/kvm` exists; otherwise TCG (slower).

### Lifecycle

```bash
make lab-qemu-images          # download / refresh cloud images
make lab-qemu-up              # build packages + boot VMs
make lab-qemu-test            # smoke-test ports / collect agent pubkeys
make lab-qemu-down            # stop VMs
```

Networking:

- Server VM publishes host ports `2222` (gateway SSH) and `8080` (API).
- Agent VMs dial **`10.0.2.2:2222`** (QEMU usermode → host → server).
- Management SSH: server `:2200`, agents `:2201`–`:2204`.

`dist/` is served over HTTP on `:8765` so cloud-init can install packages or raw binaries.

Images: `lab/qemu/images/` (gitignored). Overlays/logs: `lab/qemu/run/`.

## CVE e2e gate

```bash
make cve
ORION_CVE_E2E=1 go test ./e2e/cve/ -v
```

Requires Go **1.26.5+** (see `go.mod`).
