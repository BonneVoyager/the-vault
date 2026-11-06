#!/usr/bin/env bash
# Build, sign, notarize and package Vault.app into a .dmg. See scripts/README.md.
set -euo pipefail

SKIP_SIGN=0
SKIP_NOTARIZE=0
DRY_RUN=0

usage() {
  echo "Usage: scripts/package.sh [--skip-sign] [--skip-notarize] [--dry-run]"
}

for arg in "$@"; do
  case "$arg" in
    --skip-sign) SKIP_SIGN=1 ;;
    --skip-notarize) SKIP_NOTARIZE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "error: unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

# A notarization submission requires a signed app.
if [[ $SKIP_SIGN -eq 1 && $SKIP_NOTARIZE -eq 0 ]]; then
  echo "note: --skip-sign implies --skip-notarize"
  SKIP_NOTARIZE=1
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Check required env vars (names only, never values) before doing any work.
missing=()
if [[ $SKIP_SIGN -eq 0 && -z "${VAULT_SIGN_IDENTITY:-}" ]]; then
  missing+=(VAULT_SIGN_IDENTITY)
fi
if [[ $SKIP_NOTARIZE -eq 0 ]]; then
  if [[ -z "${VAULT_NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
    for var in VAULT_NOTARY_APPLE_ID VAULT_NOTARY_TEAM_ID VAULT_NOTARY_PASSWORD; do
      if [[ -z "${!var:-}" ]]; then
        missing+=("$var")
      fi
    done
  fi
fi
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "error: missing required environment variables:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

parse_version() {
  if command -v python3 > /dev/null 2>&1; then
    cargo metadata --no-deps --format-version 1 | python3 -c \
      'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="vault-app"))'
  elif command -v jq > /dev/null 2>&1; then
    cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name=="vault-app") | .version'
  else
    awk '/^\[/ { in_ws = ($0 == "[workspace.package]") } in_ws && /^version *=/ { gsub(/^version *= *"|".*$/, ""); print; exit }' Cargo.toml
  fi
}
VERSION="$(parse_version)"
if [[ -z "$VERSION" ]]; then
  echo "error: could not parse version from Cargo.toml" >&2
  exit 1
fi

PKG_DIR="target/package"
APP="$PKG_DIR/Vault.app"
ZIP="$PKG_DIR/Vault-$VERSION.zip"
DMG="$PKG_DIR/Vault-$VERSION.dmg"
STAGING="$PKG_DIR/dmg-staging"

# Run a command, or only print it under --dry-run. Used for signing, notarizing, dmg.
run_guarded() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run]'; printf ' %q' "$@"; echo
  else
    "$@"
  fi
}

# Temporary notarytool keychain profile, used when only Apple ID credentials are set so the
# password never appears in the argv of the long-running `submit --wait`.
TEMP_PROFILE=""
cleanup() {
  rm -rf "${STAGING:-}"
  if [[ -n "$TEMP_PROFILE" ]]; then
    # Best-effort: notarytool stores the profile as a generic password (service
    # com.apple.gke.notary.tool, account = profile name). Never fail the exit path.
    security delete-generic-password -s "com.apple.gke.notary.tool" -a "$TEMP_PROFILE" \
      >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Create the temporary profile once (short-lived argv exposure, milliseconds).
ensure_temp_profile() {
  [[ -n "$TEMP_PROFILE" ]] && return 0
  local name="vault-package-$$-$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 12)"
  TEMP_PROFILE="$name"
  xcrun notarytool store-credentials "$name" \
    --apple-id "$VAULT_NOTARY_APPLE_ID" \
    --team-id "$VAULT_NOTARY_TEAM_ID" \
    --password "$VAULT_NOTARY_PASSWORD" >/dev/null
}

# Submit a file (zip or dmg) to the notary service and wait. Secrets are never printed.
notarize_submit() {
  local file="$1"
  if [[ -n "${VAULT_NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
    run_guarded xcrun notarytool submit "$file" \
      --keychain-profile "$VAULT_NOTARY_KEYCHAIN_PROFILE" --wait
  elif [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] xcrun notarytool store-credentials <temp-profile> --apple-id <redacted> --team-id <redacted> --password <redacted> (once)"
    echo "[dry-run] xcrun notarytool submit $file --keychain-profile <temp-profile> --wait"
  else
    ensure_temp_profile
    xcrun notarytool submit "$file" --keychain-profile "$TEMP_PROFILE" --wait
  fi
}

# `dist` (workspace Cargo.toml): fat LTO, one codegen unit, stripped binary, packed dSYM.
echo "==> Building vault-app (dist profile), version $VERSION"
cargo build --profile dist -p vault-app

echo "==> Assembling $APP"
rm -rf target/package
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/dist/vault-app "$APP/Contents/MacOS/vault-app"
chmod 755 "$APP/Contents/MacOS/vault-app"
# Debug symbols for crash symbolication stay next to the bundle, never inside it.
# target/dist/vault-app.dSYM is a symlink into deps/, so copy with -L.
if [[ -d target/dist/vault-app.dSYM ]]; then
  cp -RL target/dist/vault-app.dSYM "$PKG_DIR/Vault.app.dSYM"
else
  echo "warning: target/dist/vault-app.dSYM not found; crash reports cannot be symbolicated" >&2
fi
sed "s/@VERSION@/$VERSION/g" scripts/Info.plist > "$APP/Contents/Info.plist"
if [[ -f assets/icon/Vault.icns ]]; then
  cp assets/icon/Vault.icns "$APP/Contents/Resources/Vault.icns"
else
  echo "warning: assets/icon/Vault.icns not found; run assets/icon/build-icns.sh. Bundle will have no icon." >&2
  echo "No icon. Run assets/icon/build-icns.sh and re-package." \
    > "$APP/Contents/Resources/README-icon.txt"
fi

if [[ $SKIP_SIGN -eq 1 ]]; then
  echo "==> Skipping codesign"
  echo "SKIP: entitlements check (unsigned build)"
else
  echo "==> Signing"
  run_guarded codesign --deep --options runtime --timestamp \
    --entitlements scripts/entitlements.plist \
    --sign "$VAULT_SIGN_IDENTITY" "$APP"
  echo "==> Checking entitlements and hardened runtime"
  # The spctl assessment only passes once notarized, so it is skipped before notarization.
  run_guarded scripts/check-entitlements.sh --skip-notarize "$APP"
fi

if [[ $SKIP_NOTARIZE -eq 1 ]]; then
  echo "==> Skipping notarization"
else
  echo "==> Notarizing"
  run_guarded ditto -c -k --keepParent "$APP" "$ZIP"
  notarize_submit "$ZIP"
  run_guarded xcrun stapler staple "$APP"
fi

echo "==> Creating $DMG"
mkdir -p "$STAGING"
cp -R "$APP" "$STAGING/Vault.app"
ln -s /Applications "$STAGING/Applications"
run_guarded hdiutil create -volname Vault -srcfolder "$STAGING" -ov -format UDZO "$DMG"
rm -rf "$STAGING"

if [[ $SKIP_SIGN -eq 0 ]]; then
  echo "==> Signing dmg"
  run_guarded codesign --sign "$VAULT_SIGN_IDENTITY" --timestamp "$DMG"
fi
if [[ $SKIP_NOTARIZE -eq 0 ]]; then
  echo "==> Notarizing dmg"
  notarize_submit "$DMG"
  run_guarded xcrun stapler staple "$DMG"
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "==> Dry run complete; no dmg was built"
else
  echo "==> Done: $DMG"
fi
