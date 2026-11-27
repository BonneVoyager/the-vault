#!/usr/bin/env bash
# Refuse a Vault.app whose signature weakens the hardened runtime.
# Usage: scripts/check-entitlements.sh [--skip-notarize] <path-to-Vault.app>
#        scripts/check-entitlements.sh --render <output.plist>
# With VAULT_TEAM_ID set (a Team-ID signed, Touch-ID capable build; docs/signing.md) the
# expected entitlements are scripts/entitlements.plist.in rendered for that team, and the
# signature's team and the embedded provisioning profile are checked too. Without it, the
# expected entitlements are scripts/entitlements.plist (empty). --render writes the expected
# file and exits; package.sh signs with exactly that file.
# See specs/04-macos.md section 7 and docs/research/2026-10-29-hardware-key-and-unlocked-state.md 2b.
set -euo pipefail

USAGE="usage: check-entitlements.sh [--skip-notarize] <path-to-Vault.app> | --render <output.plist>"
SKIP_NOTARIZE=0
APP=""
RENDER_OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-notarize) SKIP_NOTARIZE=1 ;;
    --render)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "error: --render needs an output path" >&2
        exit 2
      fi
      RENDER_OUT="$2"
      shift
      ;;
    -h | --help) echo "$USAGE"; exit 0 ;;
    -*) echo "error: unknown argument: $1" >&2; exit 2 ;;
    *)
      if [[ -n "$APP" ]]; then
        echo "error: exactly one app path is allowed" >&2
        echo "$USAGE" >&2
        exit 2
      fi
      APP="$1"
      ;;
  esac
  shift
done

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEAM_ID="${VAULT_TEAM_ID:-}"

# Write the expected entitlements to $1: the template rendered for TEAM_ID, or a copy of the
# empty allow-list when no Team ID is set. Team and bundle id are validated before sed sees them.
render_entitlements() {
  local out="$1"
  if [[ -z "$TEAM_ID" ]]; then
    cp "$SCRIPTS/entitlements.plist" "$out"
    return 0
  fi
  if [[ ! "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
    echo "FAIL: VAULT_TEAM_ID must be the 10-character Team ID (A-Z, 0-9)" >&2
    return 1
  fi
  local bundle_id
  bundle_id="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$SCRIPTS/Info.plist")"
  if [[ ! "$bundle_id" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "FAIL: unexpected CFBundleIdentifier in $SCRIPTS/Info.plist: $bundle_id" >&2
    return 1
  fi
  sed -e "s/@TEAM_ID@/$TEAM_ID/g" -e "s/@BUNDLE_ID@/$bundle_id/g" \
    "$SCRIPTS/entitlements.plist.in" > "$out"
  if grep -q '@[A-Z_]*@' "$out" || ! plutil -lint "$out" > /dev/null; then
    echo "FAIL: rendering $SCRIPTS/entitlements.plist.in left placeholders or invalid XML" >&2
    return 1
  fi
}

if [[ -n "$RENDER_OUT" ]]; then
  if [[ -n "$APP" ]]; then
    echo "error: --render takes no app path" >&2
    exit 2
  fi
  render_entitlements "$RENDER_OUT"
  exit 0
fi

if [[ -z "$APP" || ! -d "$APP" ]]; then
  echo "error: $USAGE" >&2
  exit 2
fi

if ! codesign --verify --strict "$APP" 2> /dev/null; then
  echo "FAIL: signature of $APP is missing or invalid (codesign --verify --strict)" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The only entitlements allowed: exactly the ones in the expected file (allow-list, review L-23).
if [[ -z "$TEAM_ID" ]]; then
  EXPECTED="$SCRIPTS/entitlements.plist"
  EXPECTED_LABEL="$EXPECTED"
  if [[ ! -f "$EXPECTED" ]]; then
    echo "FAIL: expected entitlements file $EXPECTED is missing" >&2
    exit 1
  fi
else
  EXPECTED="$tmp/expected-rendered.plist"
  EXPECTED_LABEL="$SCRIPTS/entitlements.plist.in rendered for team $TEAM_ID"
  render_entitlements "$EXPECTED"
fi
ents="$tmp/entitlements.plist"

# Extract entitlements. Newer macOS emits plain XML for ':-'; fall back to '--xml'.
# A codesign failure is fatal; only exit 0 with empty output means "no entitlements".
rc=0
codesign -d --entitlements :- "$APP" > "$tmp/raw" 2> "$tmp/err" || rc=$?
if [[ $rc -eq 0 ]] && { [[ ! -s "$tmp/raw" ]] || plutil -lint "$tmp/raw" > /dev/null 2>&1; }; then
  :
else
  rc=0
  codesign -d --entitlements - --xml "$APP" > "$tmp/raw" 2> "$tmp/err" || rc=$?
  if [[ $rc -ne 0 ]]; then
    cat "$tmp/err" >&2
    echo "FAIL: codesign could not read entitlements of $APP (exit $rc)" >&2
    exit 1
  fi
  if [[ -s "$tmp/raw" ]] && ! plutil -lint "$tmp/raw" > /dev/null 2>&1; then
    echo "FAIL: could not parse entitlements of $APP" >&2
    exit 1
  fi
fi
if [[ -s "$tmp/raw" ]]; then
  cp "$tmp/raw" "$ents"
else
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict/></plist>\n' > "$ents"
fi

# Normalise both through plutil (XML, sorted keys, comments and whitespace dropped), then
# require equality: any added, missing or changed entitlement fails.
if ! plutil -convert xml1 -o "$tmp/actual.xml" "$ents" 2> "$tmp/err"; then
  cat "$tmp/err" >&2
  echo "FAIL: could not normalise the entitlements of $APP" >&2
  exit 1
fi
if ! plutil -convert xml1 -o "$tmp/expected.xml" "$EXPECTED" 2> "$tmp/err"; then
  cat "$tmp/err" >&2
  echo "FAIL: could not normalise $EXPECTED_LABEL" >&2
  exit 1
fi
if ! diff -u "$tmp/expected.xml" "$tmp/actual.xml" >&2; then
  echo "FAIL: entitlements of $APP differ from $EXPECTED_LABEL (diff above: - expected, + signed)" >&2
  echo "FAIL: refusing to package." >&2
  exit 1
fi
echo "OK: entitlements equal $EXPECTED_LABEL"

sig="$(codesign -d -vv "$APP" 2>&1)" || { echo "FAIL: codesign -d failed for $APP" >&2; exit 1; }
if ! grep -Eq 'flags=0x[0-9a-f]+\([^)]*runtime' <<< "$sig"; then
  echo "FAIL: signature of $APP lacks the hardened runtime flag (sign with --options runtime)" >&2
  exit 1
fi
echo "OK: hardened runtime flag present"

if [[ -n "$TEAM_ID" ]]; then
  signed_team="$(sed -n 's/^TeamIdentifier=//p' <<< "$sig")"
  if [[ "$signed_team" != "$TEAM_ID" ]]; then
    echo "FAIL: $APP is signed by team '${signed_team:-none}', VAULT_TEAM_ID is $TEAM_ID" >&2
    exit 1
  fi
  echo "OK: signed by team $TEAM_ID"
  if [[ ! -f "$APP/Contents/embedded.provisionprofile" ]]; then
    echo "FAIL: $APP has no Contents/embedded.provisionprofile; the keychain entitlements need it" >&2
    exit 1
  fi
  echo "OK: provisioning profile embedded"
fi

if [[ $SKIP_NOTARIZE -eq 1 ]]; then
  echo "SKIP: spctl assessment (--skip-notarize)"
else
  if ! spctl --assess --type execute "$APP"; then
    echo "FAIL: spctl --assess rejected $APP" >&2
    exit 1
  fi
  echo "OK: spctl assessment passed"
fi
