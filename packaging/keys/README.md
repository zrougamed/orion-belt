# Packaging signing keys

This directory holds the **public** packaging key used to trust APT / RPM / APK repos.

## Generate (maintainers)

```bash
./scripts/gen-packaging-key.sh
# → orion-belt.asc / .gpg / .fingerprint
# → orion-belt.private.asc (gitignored — store in a secret manager)
```

Export the private key into CI as `GPG_PRIVATE_KEY` (+ optional `GPG_PASSPHRASE`).

## Publish signed repos

```bash
export ORION_GPG_KEY="$(cat packaging/keys/orion-belt.fingerprint)"
make packages
ORION_REQUIRE_SIGN=1 make repos
```

Clients install the public key from `repos/keys/` (or this directory) — see `packaging/repos/*.example`.

## Verify a release

```bash
gpg --import packaging/keys/orion-belt.asc
gpg --verify dist/SHA256SUMS.asc dist/SHA256SUMS
(cd dist && sha256sum -c SHA256SUMS)
```
