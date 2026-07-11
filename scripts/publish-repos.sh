#!/usr/bin/env bash
# Build APT / RPM / APK repository trees from dist/ packages, with optional GPG trust.
#
# Usage:
#   make packages
#   ./scripts/gen-packaging-key.sh   # once
#   export ORION_GPG_KEY=$(cat packaging/keys/orion-belt.fingerprint)
#   ./scripts/publish-repos.sh
#   # → repos/{apt,rpm,apk,keys} + SHA256SUMS
#
# Env:
#   ORION_GPG_KEY          GPG fingerprint / key id (required for trusted repos)
#   ORION_REQUIRE_SIGN=1   fail if signing tools/key missing
#   ORION_APK_PRIVKEY      abuild RSA private key for apk index
#   ORION_DIST / ORION_REPOS_OUT / ORION_APT_CODENAME / ORION_APT_COMPONENT
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ORION_DIST:-$ROOT/dist}"
OUT="${ORION_REPOS_OUT:-$ROOT/repos}"
CODENAME="${ORION_APT_CODENAME:-stable}"
COMPONENT="${ORION_APT_COMPONENT:-main}"
ARCHS="${ORION_REPO_ARCHS:-amd64 arm64}"
REQUIRE_SIGN="${ORION_REQUIRE_SIGN:-0}"
KEYS_SRC="${ORION_KEYS_OUT:-$ROOT/packaging/keys}"

if [[ -n "${ORION_GPG_HOME:-}" ]]; then
  export GNUPGHOME="$ORION_GPG_HOME"
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
fi

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
die() { echo "$*" >&2; exit 1; }
warn() { echo "warn: $*" >&2; }

if [[ ! -d "$DIST" ]]; then
  die "No dist/ at $DIST — run make packages first"
fi

# Resolve GPG key
KEY="${ORION_GPG_KEY:-}"
if [[ -z "$KEY" && -f "$KEYS_SRC/orion-belt.fingerprint" ]]; then
  KEY="$(tr -d '[:space:]' <"$KEYS_SRC/orion-belt.fingerprint")"
fi

shopt -s nullglob
debs=("$DIST"/*.deb)
rpms=("$DIST"/*.rpm)
apks=("$DIST"/*.apk)

echo "==> Publishing package repos from $DIST → $OUT"
rm -rf "$OUT"
mkdir -p "$OUT/keys"

# Publish public key material for clients
if [[ -f "$KEYS_SRC/orion-belt.asc" ]]; then
  cp -f "$KEYS_SRC/orion-belt.asc" "$OUT/keys/orion-belt.asc"
  cp -f "$KEYS_SRC/orion-belt.asc" "$OUT/orion-belt.asc"
fi
if [[ -f "$KEYS_SRC/orion-belt.gpg" ]]; then
  cp -f "$KEYS_SRC/orion-belt.gpg" "$OUT/keys/orion-belt.gpg"
  cp -f "$KEYS_SRC/orion-belt.gpg" "$OUT/apt/orion-belt.gpg" 2>/dev/null || true
fi
if [[ -f "$KEYS_SRC/orion-belt.fingerprint" ]]; then
  cp -f "$KEYS_SRC/orion-belt.fingerprint" "$OUT/keys/orion-belt.fingerprint"
fi

sign_ok=0
if [[ -n "$KEY" ]] && command -v gpg >/dev/null; then
  if gpg --list-secret-keys "$KEY" >/dev/null 2>&1; then
    sign_ok=1
  else
    warn "ORION_GPG_KEY=$KEY not found in secret keyring"
  fi
fi
if [[ "$REQUIRE_SIGN" == "1" && "$sign_ok" -ne 1 ]]; then
  die "ORION_REQUIRE_SIGN=1 but no usable GPG secret key (run scripts/gen-packaging-key.sh)"
fi

# ── APT ──────────────────────────────────────────────────────
if ((${#debs[@]})); then
  need gzip
  apt_root="$OUT/apt"
  pool="$apt_root/pool/$COMPONENT"
  mkdir -p "$pool"
  cp -f "${debs[@]}" "$pool/"
  if [[ -f "$KEYS_SRC/orion-belt.gpg" ]]; then
    mkdir -p "$apt_root"
    cp -f "$KEYS_SRC/orion-belt.gpg" "$apt_root/orion-belt.gpg"
    cp -f "$KEYS_SRC/orion-belt.asc" "$apt_root/orion-belt.asc"
  fi

  if command -v dpkg-scanpackages >/dev/null; then
    for arch in $ARCHS; do
      dist_dir="$apt_root/dists/$CODENAME/$COMPONENT/binary-$arch"
      mkdir -p "$dist_dir"
      (cd "$apt_root" && dpkg-scanpackages -a "$arch" "pool/$COMPONENT" /dev/null >"$dist_dir/Packages" 2>/dev/null) \
        || (cd "$apt_root" && dpkg-scanpackages "pool/$COMPONENT" /dev/null >"$dist_dir/Packages")
      gzip -9fk "$dist_dir/Packages"
    done
  else
    warn "dpkg-scanpackages missing — APT Packages indexes not generated"
  fi

  release="$apt_root/dists/$CODENAME/Release"
  mkdir -p "$(dirname "$release")"
  if command -v apt-ftparchive >/dev/null; then
    (
      cd "$apt_root"
      apt-ftparchive -o APT::FTPArchive::Release::Origin="Orion Belt" \
        -o APT::FTPArchive::Release::Label="Orion Belt" \
        -o APT::FTPArchive::Release::Suite="$CODENAME" \
        -o APT::FTPArchive::Release::Codename="$CODENAME" \
        -o APT::FTPArchive::Release::Components="$COMPONENT" \
        -o APT::FTPArchive::Release::Architectures="$ARCHS" \
        release "dists/$CODENAME" >"dists/$CODENAME/Release"
    )
  else
    {
      echo "Origin: Orion Belt"
      echo "Label: Orion Belt"
      echo "Suite: $CODENAME"
      echo "Codename: $CODENAME"
      echo "Components: $COMPONENT"
      echo "Architectures: $ARCHS"
      echo "Date: $(date -Ru)"
      echo "Acquire-By-Hash: no"
    } >"$release"
    # Append SHA256 for Packages files
    echo "SHA256:" >>"$release"
    (
      cd "$apt_root/dists/$CODENAME"
      find . -type f \( -name Packages -o -name 'Packages.gz' \) | sort | while read -r f; do
        f="${f#./}"
        size=$(wc -c <"$f" | tr -d ' ')
        hash=$(sha256sum "$f" | awk '{print $1}')
        printf " %s %8s %s\n" "$hash" "$size" "$f"
      done
    ) >>"$release"
  fi

  if [[ "$sign_ok" -eq 1 ]]; then
    rm -f "${release}.gpg" "$apt_root/dists/$CODENAME/InRelease"
    gpg --batch --yes --default-key "$KEY" -abs -o "${release}.gpg" "$release"
    gpg --batch --yes --default-key "$KEY" --clearsign -o "$apt_root/dists/$CODENAME/InRelease" "$release"
    echo "  signed APT InRelease + Release.gpg with $KEY"
  else
    echo "  APT repo ready (unsigned — set ORION_GPG_KEY / run gen-packaging-key.sh)"
  fi
  echo "  → $apt_root"
else
  echo "  skip APT (no .deb in dist/)"
fi

# ── RPM ──────────────────────────────────────────────────────
if ((${#rpms[@]})); then
  rpm_root="$OUT/rpm"
  mkdir -p "$rpm_root"
  cp -f "${rpms[@]}" "$rpm_root/"
  if [[ -f "$KEYS_SRC/orion-belt.asc" ]]; then
    cp -f "$KEYS_SRC/orion-belt.asc" "$rpm_root/orion-belt.asc"
  fi

  if [[ "$sign_ok" -eq 1 ]]; then
    if command -v rpmsign >/dev/null; then
      # Ensure rpm macros point at our key
      rpmsign --addsign --key-id="$KEY" "$rpm_root"/*.rpm
      echo "  signed RPMs with $KEY"
    else
      warn "rpmsign not found — RPMs copied unsigned"
      [[ "$REQUIRE_SIGN" == "1" ]] && die "rpmsign required"
    fi
  fi

  if command -v createrepo_c >/dev/null; then
    createrepo_c "$rpm_root"
  elif command -v createrepo >/dev/null; then
    createrepo "$rpm_root"
  else
    warn "createrepo_c not found — copied RPMs only"
  fi

  if [[ "$sign_ok" -eq 1 && -f "$rpm_root/repodata/repomd.xml" ]]; then
    rm -f "$rpm_root/repodata/repomd.xml.asc" "$rpm_root/repodata/repomd.xml.gpg"
    gpg --batch --yes --default-key "$KEY" --armor --detach-sign -o "$rpm_root/repodata/repomd.xml.asc" "$rpm_root/repodata/repomd.xml"
    echo "  signed RPM repomd.xml"
  fi
  echo "  → $rpm_root"
else
  echo "  skip RPM (no .rpm in dist/)"
fi

# ── APK ──────────────────────────────────────────────────────
if ((${#apks[@]})); then
  apk_root="$OUT/apk"
  mkdir -p "$apk_root"
  cp -f "${apks[@]}" "$apk_root/"
  if [[ -n "${ORION_APK_PUBKEY:-}" && -f "${ORION_APK_PUBKEY}" ]]; then
    cp -f "$ORION_APK_PUBKEY" "$apk_root/orion-belt.rsa.pub"
    mkdir -p "$OUT/keys"
    cp -f "$ORION_APK_PUBKEY" "$OUT/keys/orion-belt.rsa.pub"
  fi
  if command -v apk >/dev/null; then
    (
      cd "$apk_root"
      if [[ -n "${ORION_APK_PRIVKEY:-}" ]]; then
        apk index -o APKINDEX.tar.gz --rewrite-arch x86_64 ./*.apk
        if command -v abuild-sign >/dev/null; then
          abuild-sign -k "$ORION_APK_PRIVKEY" APKINDEX.tar.gz
          echo "  signed APKINDEX with ORION_APK_PRIVKEY"
        else
          warn "abuild-sign not found"
          [[ "$REQUIRE_SIGN" == "1" ]] && die "abuild-sign required"
        fi
      else
        apk index -o APKINDEX.tar.gz ./*.apk 2>/dev/null \
          || warn "apk index failed — install alpine-sdk / apk-tools"
        echo "  APK index unsigned (set ORION_APK_PRIVKEY)"
      fi
    )
  else
    warn "apk binary not found — copied packages only"
  fi
  echo "  → $apk_root"
else
  echo "  skip APK (no .apk in dist/)"
fi

# Artifact checksums + signatures for the published tree
if command -v sha256sum >/dev/null; then
  (
    cd "$OUT"
    find . -type f ! -name 'SHA256SUMS' ! -name 'SHA256SUMS.asc' ! -name '*.asc' ! -name '*.gpg' ! -name '*.example' \
      | sed 's|^\./||' | sort | while read -r f; do
      sha256sum "$f"
    done >SHA256SUMS
  )
  if [[ "$sign_ok" -eq 1 ]]; then
    gpg --batch --yes --default-key "$KEY" --armor --detach-sign -o "$OUT/SHA256SUMS.asc" "$OUT/SHA256SUMS"
    echo "  signed repos/SHA256SUMS"
  fi
fi

# Also sign dist/ artifacts if requested
if [[ "${ORION_SIGN_DIST:-1}" == "1" && "$sign_ok" -eq 1 ]]; then
  ORION_GPG_KEY="$KEY" ORION_DIST="$DIST" bash "$ROOT/scripts/sign-artifacts.sh" || warn "sign-artifacts failed"
fi

# Client snippets
cp -f "$ROOT/packaging/repos/"*.example "$OUT/" 2>/dev/null || true

cat <<EOF

Repos published under $OUT

Public key:
  $OUT/keys/orion-belt.asc
  $OUT/apt/orion-belt.gpg   (APT signed-by)

Serve over HTTPS, then clients can trust the repo (see packaging/repos/*.example).

Verify checksums:
  gpg --verify $OUT/SHA256SUMS.asc $OUT/SHA256SUMS
EOF
