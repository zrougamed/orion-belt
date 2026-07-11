#!/usr/bin/env bash
# Build APT / RPM / APK repository trees from dist/ packages.
#
# Usage:
#   make packages
#   ./scripts/publish-repos.sh
#   # → repos/apt  repos/rpm  repos/apk
#
# Serve with any static host (nginx, GitHub Pages, S3):
#   python3 -m http.server 8081 --directory repos
#
# Clients (examples under packaging/repos/):
#   apt:  deb [signed-by=…] https://packages.example.com/apt stable main
#   dnf:  baseurl=https://packages.example.com/rpm
#   apk:  https://packages.example.com/apk
#
# Optional signing:
#   ORION_GPG_KEY=…          # apt/rpm GPG fingerprint or key id
#   ORION_APK_PRIVKEY=…      # path to abuild-style RSA key for apk index
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ORION_DIST:-$ROOT/dist}"
OUT="${ORION_REPOS_OUT:-$ROOT/repos}"
CODENAME="${ORION_APT_CODENAME:-stable}"
COMPONENT="${ORION_APT_COMPONENT:-main}"
ARCHS="${ORION_REPO_ARCHS:-amd64 arm64}"

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }

if [[ ! -d "$DIST" ]]; then
  echo "No dist/ at $DIST — run make packages first" >&2
  exit 1
fi

shopt -s nullglob
debs=("$DIST"/*.deb)
rpms=("$DIST"/*.rpm)
apks=("$DIST"/*.apk)

echo "==> Publishing package repos from $DIST → $OUT"

# ── APT ──────────────────────────────────────────────────────
if ((${#debs[@]})); then
  need dpkg-scanpackages
  need gzip
  apt_root="$OUT/apt"
  pool="$apt_root/pool/$COMPONENT"
  mkdir -p "$pool"
  cp -f "${debs[@]}" "$pool/"
  for arch in $ARCHS; do
    dist_dir="$apt_root/dists/$CODENAME/$COMPONENT/binary-$arch"
    mkdir -p "$dist_dir"
    (cd "$apt_root" && dpkg-scanpackages -a "$arch" "pool/$COMPONENT" /dev/null >"$dist_dir/Packages" 2>/dev/null) \
      || (cd "$apt_root" && dpkg-scanpackages "pool/$COMPONENT" /dev/null >"$dist_dir/Packages")
    gzip -9fk "$dist_dir/Packages"
  done
  # Minimal Release file (unsigned unless ORION_GPG_KEY set)
  release="$apt_root/dists/$CODENAME/Release"
  {
    echo "Origin: Orion Belt"
    echo "Label: Orion Belt"
    echo "Suite: $CODENAME"
    echo "Codename: $CODENAME"
    echo "Components: $COMPONENT"
    echo "Architectures: $ARCHS"
    echo "Date: $(date -Ru)"
  } >"$release"
  if [[ -n "${ORION_GPG_KEY:-}" ]] && command -v gpg >/dev/null; then
    gpg --default-key "$ORION_GPG_KEY" -abs -o "${release}.gpg" "$release"
    gpg --default-key "$ORION_GPG_KEY" --clearsign -o "$apt_root/dists/$CODENAME/InRelease" "$release"
    echo "  signed APT Release with $ORION_GPG_KEY"
  else
    echo "  APT repo ready (unsigned — set ORION_GPG_KEY to sign)"
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
  if command -v createrepo_c >/dev/null; then
    createrepo_c "$rpm_root"
  elif command -v createrepo >/dev/null; then
    createrepo "$rpm_root"
  else
    echo "  warn: createrepo_c not found — copied RPMs only" >&2
  fi
  if [[ -n "${ORION_GPG_KEY:-}" ]] && command -v rpmsign >/dev/null; then
    rpmsign --addsign --key-id="$ORION_GPG_KEY" "$rpm_root"/*.rpm || true
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
  if command -v apk >/dev/null; then
    (
      cd "$apk_root"
      if [[ -n "${ORION_APK_PRIVKEY:-}" ]]; then
        apk index -o APKINDEX.tar.gz --rewrite-arch x86_64 ./*.apk
        abuild-sign -k "$ORION_APK_PRIVKEY" APKINDEX.tar.gz 2>/dev/null \
          || echo "  warn: abuild-sign failed; index unsigned" >&2
      else
        apk index -o APKINDEX.tar.gz ./*.apk 2>/dev/null \
          || echo "  warn: apk index failed — install alpine-sdk / apk-tools" >&2
      fi
    )
  else
    echo "  warn: apk binary not found — copied packages only" >&2
  fi
  echo "  → $apk_root"
else
  echo "  skip APK (no .apk in dist/)"
fi

# Client snippets
mkdir -p "$OUT"
cp -f "$ROOT/packaging/repos/"*.example "$OUT/" 2>/dev/null || true

cat <<EOF

Repos published under $OUT

Serve:
  python3 -m http.server 8081 --directory $OUT

Or sync to your CDN / GitHub Pages / S3.
Client snippets: packaging/repos/*.example
EOF
