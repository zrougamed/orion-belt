# Shipping v1.0.0

v1.0 is not a giant new feature. It’s when we say the SSH bastion/PAM stack (CA, MFA, JIT, ReBAC, recording, live watch, packages) is what we’re calling **1.0**, and we’ll keep `/api/v1` honest under semver.

OIDC, HA, RDP/VNC, SDKs, and compliance packs wait until after 1.0.

## Checklist (for the cut)

### API

- [x] Compatibility notes: [API_STABILITY.md](API_STABILITY.md)
- [x] OpenAPI `info.version` is `1.0.0`
- [x] Release notes cover what landed since `v0.8.1` (permissions, compression, watch, prefs, JIT, docs)

### Ops docs

| Doc | Why |
|-----|-----|
| [SETUP.md](SETUP.md) | get a server running |
| [DEPLOYMENT_HARDENING.md](DEPLOYMENT_HARDENING.md) | don’t leave defaults wide open |
| [OBSERVABILITY.md](OBSERVABILITY.md) | logs + `/metrics` + example alerts |

Postgres backup (lab is fine):

```bash
pg_dump "$DATABASE_URL" -Fc -f orion-belt-$(date +%Y%m%d).dump
# pg_restore --clean --if-exists -d "$RESTORE_URL" orion-belt-YYYYMMDD.dump
```

Also back up `recording.storage_path` if you care about audits. 1.0 assumes **one gateway + Postgres backups**, not a cluster.

### Smoke

- [x] [RELEASE_SMOKE.md](RELEASE_SMOKE.md) + `make release-smoke` documented
- [ ] Run smoke / QEMU against the build you’re about to tag (your call before `git tag`)

## Tagging (you do this)

1. Commit the version bumps  
2. `git tag v1.0.0` and cut packages as usual  
3. Paste the release notes; link this page if you want  
