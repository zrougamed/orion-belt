# API compatibility (`/api/v1`)

For **v1.x** we treat the documented HTTP API as something you can build against without us breaking you on a whim.

## What we mean

- Paths under `/api/v1/*` that appear in [openapi/openapi.yaml](openapi/openapi.yaml) are the contract.
- `/health` and `/metrics` stay available. We may add fields; we won’t yank the ones you already use without a major bump.
- WebSockets under `/api/v1` (terminal, live watch) keep the same auth style and framing described in the OpenAPI notes.

If we have to break something, that is a **major** version (`v2` / a new API prefix or a clear migration note). Additive endpoints and optional fields land in minors.

## Practical rules

1. Don’t remove or rename documented JSON fields in a minor release.
2. New response fields are fine — ignore what you don’t know.
3. New optional request fields get sane defaults.
4. If we deprecate something, we’ll say so in the release notes and leave it around for at least one minor before removing it in a major.

## Not covered

- CLI flag churn (we’ll warn when we can)
- Recording file layout on disk, as long as playback / content API still works
- DB schema details (upgrades within v1.x should just migrate forward)
- Undocumented knobs

Diff the OpenAPI file between tags, or hit `GET /api/v1/openapi.yaml` on a running server. See also [RELEASE_SMOKE.md](RELEASE_SMOKE.md).
