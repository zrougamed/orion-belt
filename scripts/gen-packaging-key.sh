#!/usr/bin/env bash
# Generate (or export) the Orion Belt packaging GPG key for APT/RPM repos.
#
# Usage:
#   ./scripts/gen-packaging-key.sh              # create if missing, export pubs
#   ./scripts/gen-packaging-key.sh --force      # rotate (new key)
#
# Env:
#   ORION_GPG_NAME     default: Orion Belt Packaging
#   ORION_GPG_EMAIL    default: packaging@orion-belt.dev
#   ORION_GPG_HOME     optional isolated GNUPGHOME
#   ORION_KEYS_OUT     default: packaging/keys
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ORION_KEYS_OUT:-$ROOT/packaging/keys}"
NAME="${ORION_GPG_NAME:-Orion Belt Packaging}"
EMAIL="${ORION_GPG_EMAIL:-packaging@orion-belt.dev}"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

if [[ -n "${ORION_GPG_HOME:-}" ]]; then
  export GNUPGHOME="$ORION_GPG_HOME"
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
fi

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need gpg
mkdir -p "$OUT"

existing="$(gpg --list-secret-keys --with-colons "$EMAIL" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}' || true)"

if [[ -n "$existing" && "$FORCE" -eq 0 ]]; then
  echo "==> Reusing existing packaging key for $EMAIL"
  FPR="$existing"
else
  if [[ -n "$existing" && "$FORCE" -eq 1 ]]; then
    echo "==> Rotating packaging key (old fingerprint $existing remains in keyring)"
  fi
  echo "==> Generating packaging GPG key for $NAME <$EMAIL>"
  batch="$(mktemp)"
  trap 'rm -f "$batch"' EXIT
  cat >"$batch" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: $NAME
Name-Email: $EMAIL
Expire-Date: 3y
%commit
EOF
  gpg --batch --generate-key "$batch"
  FPR="$(gpg --list-secret-keys --with-colons "$EMAIL" | awk -F: '/^fpr:/ {print $10; exit}')"
fi

if [[ -z "$FPR" ]]; then
  echo "failed to resolve key fingerprint" >&2
  exit 1
fi

ASC="$OUT/orion-belt.asc"
GPG="$OUT/orion-belt.gpg"
gpg --armor --export "$FPR" >"$ASC"
gpg --export "$FPR" >"$GPG"
echo "$FPR" >"$OUT/orion-belt.fingerprint"

# Convenience: also export private key for operators who want a backup
# (never commit this file — it is gitignored).
PRIV="$OUT/orion-belt.private.asc"
if [[ ! -f "$PRIV" || "$FORCE" -eq 1 ]]; then
  gpg --armor --export-secret-keys "$FPR" >"$PRIV"
  chmod 600 "$PRIV"
fi

cat <<EOF

Packaging key ready
  fingerprint: $FPR
  public (ASCII): $ASC
  public (binary): $GPG
  private backup: $PRIV  (gitignored — store in a secret manager)

Use with repos:
  export ORION_GPG_KEY=$FPR
  make packages && make repos

Verify:
  gpg --verify checksums.txt.asc checksums.txt
EOF
