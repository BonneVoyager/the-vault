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

# Team-ID signed build (Touch ID needs the data-protection keychain; review I-01,
# docs/signing.md). Only with VAULT_TEAM_ID set; without it nothing below changes the build.
TEAM_ID="${VAULT_TEAM_ID:-}"
if [[ -n "$TEAM_ID" && $SKIP_SIGN -eq 1 ]]; then
  echo "note: --skip-sign ignores VAULT_TEAM_ID and VAULT_PROVISION_PROFILE (unsigned build)"
  TEAM_ID=""
fi
if [[ -n "$TEAM_ID" ]]; then
  if [[ ! "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
    echo "error: VAULT_TEAM_ID must be the 10-character Team ID (A-Z, 0-9)" >&2
    exit 1
  fi
  PROFILE="${VAULT_PROVISION_PROFILE:-}"
  if [[ -z "$PROFILE" || ! -f "$PROFILE" ]]; then
    echo "error: VAULT_TEAM_ID is set, so VAULT_PROVISION_PROFILE must name an existing" >&2
    echo "       Developer ID .provisionprofile for this bundle id (see docs/signing.md)" >&2
    exit 1
  fi
  BUNDLE_ID="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" scripts/Info.plist)"
  # The profile is CMS-signed; read its team and App ID (keys contain dots, so PlistBuddy).
  profile_plist="$(mktemp)"
  if ! security cms -D -i "$PROFILE" > "$profile_plist" 2> /dev/null; then
    rm -f "$profile_plist"
    echo "error: VAULT_PROVISION_PROFILE is not a readable provisioning profile" >&2
    exit 1
  fi
  profile_team="$(/usr/libexec/PlistBuddy -c "Print :TeamIdentifier:0" "$profile_plist" 2> /dev/null || true)"
  profile_app_id="$(/usr/libexec/PlistBuddy \
    -c "Print :Entitlements:com.apple.application-identifier" "$profile_plist" 2> /dev/null || true)"
  profile_kag="$(/usr/libexec/PlistBuddy \
    -c "Print :Entitlements:keychain-access-groups" "$profile_plist" 2> /dev/null || true)"
  rm -f "$profile_plist"
  if [[ "$profile_team" != "$TEAM_ID" ]]; then
    echo "error: provisioning profile team is '${profile_team:-none}', VAULT_TEAM_ID is $TEAM_ID" >&2
    exit 1
  fi
  if [[ "$profile_app_id" != "$TEAM_ID.$BUNDLE_ID" ]]; then
    echo "error: provisioning profile App ID is '${profile_app_id:-none}', expected $TEAM_ID.$BUNDLE_ID" >&2
    echo "       (create the profile for the explicit App ID $BUNDLE_ID, not a wildcard)" >&2
    exit 1
  fi
  # PlistBuddy prints the array one entry per line; the group must be allowed exactly or by
  # the team wildcard.
  if ! sed 's/^[[:space:]]*//; s/[[:space:]]*$//' <<< "$profile_kag" \
    | grep -qxF -e "$TEAM_ID.$BUNDLE_ID" -e "$TEAM_ID.*"; then
    echo "error: provisioning profile does not allow keychain group $TEAM_ID.$BUNDLE_ID; enable Keychain Sharing" >&2
    echo "       on the App ID and regenerate the profile (see docs/signing.md)" >&2
    exit 1
  fi
  # Best effort: the identity's certificate subject carries the team as OU. A SHA-1 identity
  # or a name `security` cannot match is not fatal; check-entitlements.sh verifies the
  # signature's TeamIdentifier after signing either way.
  cert_ou=""
  if cert_pem="$(security find-certificate -c "$VAULT_SIGN_IDENTITY" -p 2> /dev/null)" \
    && [[ -n "$cert_pem" ]]; then
    cert_ou="$(openssl x509 -noout -subject <<< "$cert_pem" 2> /dev/null \
      | grep -Eo 'OU ?= ?[A-Z0-9]{10}' | head -n 1 | grep -Eo '[A-Z0-9]{10}$' || true)"
  fi
  if [[ -z "$cert_ou" ]]; then
    echo "warning: could not read the team of VAULT_SIGN_IDENTITY; it is checked after signing" >&2
  elif [[ "$cert_ou" != "$TEAM_ID" ]]; then
    echo "error: VAULT_SIGN_IDENTITY belongs to team $cert_ou, VAULT_TEAM_ID is $TEAM_ID" >&2
    exit 1
  fi
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

# Revision recorded in the bundle (Info.plist key VaultGitRevision); "-dirty" when the work
# tree has any change, untracked files included, "unknown" outside a git checkout.
if REVISION="$(git rev-parse --verify HEAD 2> /dev/null)"; then
  if [[ -n "$(git status --porcelain 2> /dev/null)" ]]; then
    REVISION="$REVISION-dirty"
  fi
else
  REVISION="unknown"
fi

# Dependency gate (licences, sources, bans, advisories in deny.toml) before anything is built.
if ! command -v cargo-deny > /dev/null 2>&1; then
  echo "error: cargo-deny is not installed (cargo install --locked cargo-deny)" >&2
  exit 1
fi
echo "==> cargo deny check"
if ! cargo deny check; then
  echo "error: cargo deny check failed; refusing to build a release" >&2
  exit 1
fi

# Keep builder paths out of the binary and the dSYM: the home directory, then the more specific
# cargo registry and git checkouts and this checkout (rustc applies the last matching prefix).
# RUSTFLAGS is space-separated, so paths with whitespace are refused rather than mis-split.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
for p in "$HOME" "$CARGO_HOME_DIR" "$PWD"; do
  if [[ "$p" =~ [[:space:]] ]]; then
    echo "error: path contains whitespace, cannot remap it via RUSTFLAGS: $p" >&2
    exit 1
  fi
done
REMAP="--remap-path-prefix=$HOME=/home"
REMAP+=" --remap-path-prefix=$CARGO_HOME_DIR/registry/src=/cargo/registry/src"
REMAP+=" --remap-path-prefix=$CARGO_HOME_DIR/git/checkouts=/cargo/git"
REMAP+=" --remap-path-prefix=$PWD=/vault"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }$REMAP"

# `dist` (workspace Cargo.toml): fat LTO, one codegen unit, stripped binary, packed dSYM.
echo "==> Building vault-app (dist profile), version $VERSION, revision $REVISION"
cargo build --locked --profile dist -p vault-app
leaked="$(strings -a target/dist/vault-app | grep -cF "$HOME" || true)"
if [[ "$leaked" -ne 0 ]]; then
  echo "warning: $leaked strings in the binary still contain the home directory" >&2
fi

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
/usr/libexec/PlistBuddy -c "Add :VaultGitRevision string $REVISION" "$APP/Contents/Info.plist"
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
  ENTITLEMENTS=scripts/entitlements.plist
  if [[ -n "$TEAM_ID" ]]; then
    # Rendered by check-entitlements.sh, the same code that later checks equality with it.
    ENTITLEMENTS="$PKG_DIR/entitlements.rendered.plist"
    echo "==> Rendering entitlements for team $TEAM_ID; embedding provisioning profile"
    scripts/check-entitlements.sh --render "$ENTITLEMENTS"
    cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
    chmod 644 "$APP/Contents/embedded.provisionprofile"
  fi
  echo "==> Signing"
  # --deep is fine while the bundle holds one Mach-O (Contents/MacOS/vault-app). Once it gains
  # nested code (Frameworks, helpers, XPC services, login items), sign each item inside-out
  # with its own entitlements and drop --deep (review I-14).
  run_guarded codesign --deep --options runtime --timestamp \
    --entitlements "$ENTITLEMENTS" \
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
