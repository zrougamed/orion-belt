#!/usr/bin/env bash
# Sign release artifacts under dist/ (SHA256SUMS + detached GPG signatures).
#
# Usage:
#   ORION_GPG_KEY=<fpr> ./scripts/sign-artifacts.sh
#
# Produces:
#   dist/SHA256SUMS
#   dist/SHA256SUMS.asc
#   dist/<artifact>.asc   (detached signature per package/binary/archive, optional)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ORION_DIST:-$ROOT/dist}"
KEY="${ORION_GPG_KEY:-}"
SIGN_EACH="${ORION_SIGN_EACH:-1}"

if [[ -n "${ORION_GPG_HOME:-}" ]]; then
  export GNUPGHOME="$ORION_GPG_HOME"
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
fi

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need gpg
need sha256sum

if [[ ! -d "$DIST" ]]; then
  echo "No dist/ at $DIST" >&2
  exit 1
fi
if [[ -z "$KEY" ]]; then
  if [[ -f "$ROOT/packaging/keys/orion-belt.fingerprint" ]]; then
    KEY="$(tr -d '[:space:]' <"$ROOT/packaging/keys/orion-belt.fingerprint")"
  fi
fi
if [[ -z "$KEY" ]]; then
  echo "Set ORION_GPG_KEY (fingerprint) or run ./scripts/gen-packaging-key.sh" >&2
  exit 1
fi

echo "==> Signing artifacts in $DIST with $KEY"

(
  cd "$DIST"
  shopt -s nullglob
  files=(*.deb *.rpm *.apk *.tar.gz *.txt)
  # Exclude previous signature / sum files from the checksum list
  list=()
  for f in "${files[@]}"; do
    case "$f" in
      SHA256SUMS|SHA256SUMS.asc|checksums.txt|checksums.txt.asc|*.sig|*.asc) continue ;;
    esac
    [[ -f "$f" ]] || continue
    list+=("$f")
  done
  if ((${#list[@]} == 0)); then
    echo "nothing to sign in $DIST" >&2
    exit 1
  fi
  sha256sum "${list[@]}" | sort -k2 >SHA256SUMS
  rm -f SHA256SUMS.asc
  gpg --batch --yes --default-key "$KEY" --armor --detach-sign -o SHA256SUMS.asc SHA256SUMS
  echo "  wrote SHA256SUMS + SHA256SUMS.asc"

  if [[ "$SIGN_EACH" == "1" ]]; then
    for f in "${list[@]}"; do
      rm -f "${f}.asc"
      gpg --batch --yes --default-key "$KEY" --armor --detach-sign -o "${f}.asc" "$f"
    done
    echo "  wrote per-file .asc signatures (${#list[@]} files)"
  fi
)

echo "Verify with:"
echo "  gpg --verify $DIST/SHA256SUMS.asc $DIST/SHA256SUMS"
echo "  (cd $DIST && sha256sum -c SHA256SUMS)"
