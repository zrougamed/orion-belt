#!/usr/bin/env bash
# Download (or refresh) cloud images from distros.yaml into lab/qemu/images/
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_DIR="${LAB}/images"
mkdir -p "$IMG_DIR"

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
need curl
need python3

REFRESH="${ORION_REFRESH_IMAGES:-0}"

# Optionally resolve Alpine "latest" nocloud bios-cloudinit from the v3.22 tree
resolve_alpine_latest() {
  python3 - <<'PY'
import re, urllib.request
url = "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/"
html = urllib.request.urlopen(url, timeout=60).read().decode()
names = re.findall(r'href="(nocloud_alpine-[^"]*x86_64-bios-cloudinit-r0\.qcow2)"', html)
if not names:
    raise SystemExit("no alpine nocloud image found")
names.sort(key=lambda s: [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', s)])
print(url + names[-1])
PY
}

ALPINE_URL="$(resolve_alpine_latest)"
echo "Resolved latest Alpine image: $ALPINE_URL"

python3 - <<PY
import os, sys, urllib.request
from pathlib import Path

path, out = Path("$LAB/distros.yaml"), Path("$IMG_DIR")
refresh = os.environ.get("ORION_REFRESH_IMAGES", "0") == "1"
alpine_override = """$ALPINE_URL""".strip()

text = path.read_text()
current = None
urls = {}
for line in text.splitlines():
    if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
        current = line.strip().rstrip(":")
    elif current and line.strip().startswith("url:"):
        urls[current] = line.split("url:", 1)[1].strip()

if alpine_override:
    urls["alpine"] = alpine_override

for name, url in urls.items():
    dest = out / f"{name}.qcow2"
    if dest.exists() and dest.stat().st_size > 1_000_000 and not refresh:
        print(f"skip {name} (exists; set ORION_REFRESH_IMAGES=1 to re-download)")
        continue
    print(f"download {name}: {url}")
    tmp = dest.with_suffix(".partial")
    req = urllib.request.Request(url, headers={"User-Agent": "orion-belt-lab/1.0"})
    with urllib.request.urlopen(req, timeout=600) as resp, open(tmp, "wb") as fh:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            fh.write(chunk)
    tmp.rename(dest)
    print(f"  -> {dest} ({dest.stat().st_size} bytes)")
PY

echo "Images ready in $IMG_DIR"
ls -lh "$IMG_DIR"
