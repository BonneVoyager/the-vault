#!/usr/bin/env bash
# Refuse a Vault.app whose signature weakens the hardened runtime.
# Usage: scripts/check-entitlements.sh [--skip-notarize] <path-to-Vault.app>
# See specs/04-macos.md section 7 and docs/research/2026-10-29-hardware-key-and-unlocked-state.md 2b.
set -euo pipefail

SKIP_NOTARIZE=0
APP=""
for arg in "$@"; do
  case "$arg" in
    --skip-notarize) SKIP_NOTARIZE=1 ;;
    -h | --help) echo "Usage: scripts/check-entitlements.sh [--skip-notarize] <path-to-Vault.app>"; exit 0 ;;
    -*) echo "error: unknown argument: $arg" >&2; exit 2 ;;
    *)
      if [[ -n "$APP" ]]; then
        echo "error: exactly one app path is allowed" >&2
        echo "usage: check-entitlements.sh [--skip-notarize] <path-to-Vault.app>" >&2
        exit 2
      fi
      APP="$arg"
      ;;
  esac
done
if [[ -z "$APP" || ! -d "$APP" ]]; then
  echo "error: usage: check-entitlements.sh [--skip-notarize] <path-to-Vault.app>" >&2
  exit 2
fi

# The only entitlements allowed: exactly the ones in this file (allow-list, review L-23).
EXPECTED="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/entitlements.plist"
if [[ ! -f "$EXPECTED" ]]; then
  echo "FAIL: expected entitlements file $EXPECTED is missing" >&2
  exit 1
fi

if ! codesign --verify --strict "$APP" 2> /dev/null; then
  echo "FAIL: signature of $APP is missing or invalid (codesign --verify --strict)" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
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
  echo "FAIL: could not normalise $EXPECTED" >&2
  exit 1
fi
if ! diff -u "$tmp/expected.xml" "$tmp/actual.xml" >&2; then
  echo "FAIL: entitlements of $APP differ from $EXPECTED (diff above: - expected, + signed)" >&2
  echo "FAIL: refusing to package." >&2
  exit 1
fi
echo "OK: entitlements equal $EXPECTED"

sig="$(codesign -d -vv "$APP" 2>&1)" || { echo "FAIL: codesign -d failed for $APP" >&2; exit 1; }
if ! grep -Eq 'flags=0x[0-9a-f]+\([^)]*runtime' <<< "$sig"; then
  echo "FAIL: signature of $APP lacks the hardened runtime flag (sign with --options runtime)" >&2
  exit 1
fi
echo "OK: hardened runtime flag present"

if [[ $SKIP_NOTARIZE -eq 1 ]]; then
  echo "SKIP: spctl assessment (--skip-notarize)"
else
  if ! spctl --assess --type execute "$APP"; then
    echo "FAIL: spctl --assess rejected $APP" >&2
    exit 1
  fi
  echo "OK: spctl assessment passed"
fi
