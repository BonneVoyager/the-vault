#!/usr/bin/env bash
# Rebuilds fuzz/corpus/ from the committed fixtures. Idempotent; the corpus is gitignored.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fixtures="$here/../crates/vault-core/tests/fixtures"
corpus="$here/corpus"
mkdir -p "$corpus"/{vault_parse,inner_payload,import_kdbx,import_1pux}
cp "$fixtures"/*.vault "$corpus/vault_parse/"
cp "$fixtures"/*.kdbx "$corpus/import_kdbx/"
cd "$here"
cargo +nightly run --quiet --release --bin seed -- "$fixtures" "$corpus"
for t in vault_parse inner_payload import_kdbx import_1pux; do
  echo "$t: $(ls "$corpus/$t" | wc -l | tr -d ' ') seeds"
done
