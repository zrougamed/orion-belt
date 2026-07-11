# QEMU multi-distro lab

See [../README.md](../README.md) for image pins and overview.

## Recommended

```bash
make -C ../.. lab-qemu-clean    # wipe VMs + images + credentials (default)
make -C ../.. lab-qemu-start    # clean + boot + admin + agents + users + SSH howto
```

Or one shot: `make -C ../.. lab-qemu-start` (cleans first unless `SKIP_CLEAN=1`).

**E2E QA test plan (steps + expected results):** [../docs/E2E_TEST_PLAN.md](../docs/E2E_TEST_PLAN.md)

## Scripts

| Script | Role |
|--------|------|
| `clean.sh` | Stop VMs; delete `run/`, `images/`, `credentials/` (opt-out: `KEEP_IMAGES`, `KEEP_CREDS`) |
| `start.sh` | Full pipeline (clean → up → admin → agents → seed users → SSH howto) |
| `up.sh` / `down.sh` | Boot / stop VMs only |
| `restart.sh` | Restart VMs in place (reuse disks; optional names) |
| `update-bins.sh` | Rebuild binaries, push to VMs, reload server/agents |
| `bootstrap-admin` (../) | Create admin + print UI login |
| `connect-agents.sh` | Collect keys, register, restart agents |
| `seed-users.sh` | operator / auditor / alice / bob + grants |
| `print-ssh-howto.sh` | OpenSSH examples from this host |
| `ssh.sh` | SSH into server/agent VMs |

## Demo RBAC

| User | Role | Access |
|------|------|--------|
| `admin` | admin | all |
| `operator` | operator | all agents |
| `auditor` | auditor | no machine grants |
| `alice` | user | `agent-alpine` only |
| `bob` | user | `agent-debian` (ssh) only |

Keys: `lab/credentials/*_ed25519` (+ `.pub`). Summary: `lab/credentials/USERS.txt`.

## Env

| Variable | Default | Meaning |
|----------|---------|---------|
| `SKIP_CLEAN` | `0` | `1` = start without wiping |
| `KEEP_IMAGES` | `0` | `1` = keep downloaded qcow2 on clean |
| `KEEP_CREDS` | `0` | `1` = keep `lab/credentials` on clean |
| `ORION_API` | `http://127.0.0.1:8080` | API base |
| `ORION_WAIT_SECS` | `600` (start) | API wait budget |
| `VMS` | _(all with disks)_ | `lab-qemu-restart` subset, e.g. `server alpine` |
| `AGENTS` | _(all)_ | `lab-qemu-update` / `lab-qemu-connect-agents` subset |
| `SKIP_BUILD` | `0` | `1` = reuse `dist/` binaries on `lab-qemu-update` |
