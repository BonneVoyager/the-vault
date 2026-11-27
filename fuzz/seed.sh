#!/usr/bin/env bash
# Rebuilds fuzz/corpus/ (gitignored) from the committed fixtures and the committed seeds/.
# Idempotent. The seeder also rewrites seeds/ (deterministic: no diff when nothing changed).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fixtures="$here/../crates/vault-core/tests/fixtures"
corpus="$here/corpus"
seeds="$here/seeds"
targets="vault_parse inner_payload import_kdbx import_1pux import_csv totp_uri attachment_blob export_csv_roundtrip"
for t in $targets; do mkdir -p "$corpus/$t"; done
cp "$fixtures"/*.vault "$corpus/vault_parse/"
cp "$fixtures"/*.kdbx "$corpus/import_kdbx/"
cd "$here"
cargo +nightly run --quiet --release --bin seed -- "$fixtures" "$corpus" "$seeds"
for t in import_csv totp_uri attachment_blob export_csv_roundtrip; do
  cp "$seeds/$t"/* "$corpus/$t/"
done
for t in $targets; do
  echo "$t: $(ls "$corpus/$t" | wc -l | tr -d ' ') seeds"
done
