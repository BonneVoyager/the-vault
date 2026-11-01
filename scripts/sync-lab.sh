#!/usr/bin/env bash
# One-Mac multi-device sync lab driven through the vault CLI.
# Usage: scripts/sync-lab.sh [--continue] [--keep] [--scenario NAME]
#        scripts/sync-lab.sh --random --seed N --steps M [--keep]
#        scripts/sync-lab.sh --selfcheck [--seed N --steps M]   (a seed must replay identically)
# Builds vault-cli first (set VAULT_BIN to use another binary). Stops at the first failing scenario
# unless --continue; the lab directory of a failure is kept and its path printed. See scripts/README.md.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$ROOT/scripts/sync-lab"
TMPBASE="$HERE/tmp"
KEEP=0 CONTINUE=0 RANDOM_MODE=0 SELFCHECK=0 SEED=1 STEPS=100 ONLY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --continue) CONTINUE=1 ;;
    --random) RANDOM_MODE=1 ;;
    --selfcheck) SELFCHECK=1 ;;
    --seed) SEED="$2"; shift ;;
    --steps) STEPS="$2"; shift ;;
    --scenario) ONLY="$2"; shift ;;
    -h | --help) sed -n 2,7p "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

if [ -n "${VAULT_BIN:-}" ]; then
  V="$VAULT_BIN"
else
  V="$ROOT/target/debug/vault"
  (cd "$ROOT" && cargo build -q -p vault-cli) || { echo "cargo build -p vault-cli failed" >&2; exit 2; }
fi
[ -x "$V" ] || { echo "missing $V" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

# shellcheck source=sync-lab/lib.sh
. "$HERE/lib.sh"
# shellcheck source=sync-lab/scenarios.sh
. "$HERE/scenarios.sh"
# shellcheck source=sync-lab/random.sh
. "$HERE/random.sh"

mkdir -p "$TMPBASE" && RUNDIR="$(mktemp -d "$TMPBASE/run-XXXXXX")" || exit 2
case "$RUNDIR" in "$TMPBASE/"?*) ;; *) echo "bad run dir" >&2; exit 2 ;; esac
PASS=0 FAIL=0
cleanup() {
  if [ "$KEEP" = 1 ] || [ "$FAIL" -gt 0 ]; then echo "kept $RUNDIR"; else safe_rm "$RUNDIR"; fi
}
trap cleanup EXIT

report() { # report name
  if [ -z "$SCN_FAILS" ]; then
    PASS=$((PASS + 1)); echo "PASS $1"
  else
    FAIL=$((FAIL + 1)); echo "FAIL $1$SCN_FAILS"
    echo "     lab directory: $LAB"
  fi
}

if [ "$SELFCHECK" = 1 ]; then
  selfcheck_replay "$SEED" "$STEPS"
  report "replay determinism seed=$SEED steps=$STEPS"
elif [ "$RANDOM_MODE" = 1 ]; then
  echo "random mode: seed=$SEED steps=$STEPS"
  random_run "$SEED" "$STEPS"
  report "random seed=$SEED steps=$STEPS"
else
  for s in $SCENARIOS; do
    if [ -n "$ONLY" ] && [ "$ONLY" != "$s" ]; then continue; fi
    lab_begin "$s"
    "$s"
    report "$s"
    if [ "$FAIL" -gt 0 ] && [ "$CONTINUE" = 0 ]; then break; fi
  done
fi
echo
echo "sync-lab: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
