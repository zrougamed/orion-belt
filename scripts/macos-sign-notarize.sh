#!/usr/bin/env bash
# Sign and notarize macOS CLI binaries (osh / ocp / oadmin).
# Requires: macOS, Xcode CLT, Developer ID Application cert in keychain,
# and notarytool credentials (API key or Apple ID).
#
# Usage:
#   DEVELOPER_ID_APPLICATION="Developer ID Application: Name (TEAMID)" \
#   APPLE_TEAM_ID=TEAMID \
#   APPLE_ID=you@example.com APPLE_APP_SPECIFIC_PASSWORD=xxxx \
#   ./scripts/macos-sign-notarize.sh path/to/osh path/to/ocp path/to/oadmin
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: must run on macOS" >&2
  exit 1
fi

: "${DEVELOPER_ID_APPLICATION:?set DEVELOPER_ID_APPLICATION}"
: "${APPLE_TEAM_ID:?set APPLE_TEAM_ID}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 binary [binary...]" >&2
  exit 1
fi

ENTITLEMENTS="$(mktemp -t orion-entitlements.XXXXXX).plist"
trap 'rm -f "$ENTITLEMENTS" "$ZIP"' EXIT

# Hardened runtime entitlements suitable for network CLIs.
cat >"$ENTITLEMENTS" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
  <false/>
  <key>com.apple.security.network.client</key>
  <true/>
</dict>
</plist>
EOF

for bin in "$@"; do
  if [[ ! -f "$bin" ]]; then
    echo "error: missing $bin" >&2
    exit 1
  fi
  echo "==> codesign $bin"
  codesign --force --options runtime --timestamp \
    --entitlements "$ENTITLEMENTS" \
    --sign "$DEVELOPER_ID_APPLICATION" \
    "$bin"
  codesign --verify --verbose=2 "$bin"
done

ZIP="$(mktemp -t orion-notarize.XXXXXX).zip"
echo "==> zip for notarytool → $ZIP"
# ditto preserves xattrs better than zip for Apple tooling
ditto -c -k --keepParent "$@" "$ZIP" 2>/dev/null || {
  # fallback when multiple top-level files: stage in a dir
  STAGE="$(mktemp -d -t orion-stage)"
  cp "$@" "$STAGE/"
  ditto -c -k --keepParent "$STAGE" "$ZIP"
  rm -rf "$STAGE"
}

AUTH_ARGS=()
if [[ -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_KEY_ID:-}" && -n "${APPLE_API_ISSUER:-}" ]]; then
  KEY_FILE="$(mktemp -t AuthKey.XXXXXX).p8"
  printf '%s\n' "$APPLE_API_KEY" >"$KEY_FILE"
  AUTH_ARGS=(--key "$KEY_FILE" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER")
  trap 'rm -f "$ENTITLEMENTS" "$ZIP" "$KEY_FILE"' EXIT
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
  AUTH_ARGS=(--apple-id "$APPLE_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD" --team-id "$APPLE_TEAM_ID")
else
  echo "error: set APPLE_API_KEY+APPLE_API_KEY_ID+APPLE_API_ISSUER or APPLE_ID+APPLE_APP_SPECIFIC_PASSWORD" >&2
  exit 1
fi

echo "==> notarytool submit"
xcrun notarytool submit "$ZIP" --wait "${AUTH_ARGS[@]}"

echo "==> done. Prefer packaging these binaries into a signed .pkg/.dmg for stapling;"
echo "    bare CLIs rely on online notarization ticket lookup after first launch."
echo "    Verify:  codesign -dv --verbose=4 <binary>"
