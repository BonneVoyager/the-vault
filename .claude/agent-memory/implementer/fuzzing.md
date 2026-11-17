---
name: fuzzing
description: cargo-fuzz setup in fuzz/ (own workspace), toolchain gotchas, VaultKeyHandle seed-key trick, cmin renames seeds
metadata:
  type: project
---

`fuzz/` is a standalone cargo-fuzz package (`[workspace]` table in fuzz/Cargo.toml), so the root
Cargo.toml needed no `exclude`. Targets: vault_parse, inner_payload, import_kdbx, import_1pux.
vault-core deps with features `sync` + `kdbx`. Corpora committed; artifacts/target gitignored.

Gotchas (2026-11-17):
- `cargo install cargo-fuzz` fails under the default `stable` (1.89, too old for cargo-platform);
  use `cargo +nightly install cargo-fuzz --locked`. Nightly minimal profile has no clippy; lint
  the fuzz crate with the pinned toolchain plus a /tmp `--target-dir`.
- `VaultKeyHandle` has no raw-bytes constructor, so "all-zero vault key" is impossible; the target
  unlocks v2-basic.vault once (OnceLock) with the fixture password and uses that handle, so seed
  mutants with the same vault_id reach `decode_item_plain`.
- `format::decode_item_plain` / `decode_manifest` / `encode_item_plain` are `pub` (format is a pub mod).
- `cargo fuzz cmin` renames every file to a content hash and may drop named seeds; copy fixtures back.
- Seed generators belong outside the repo (/tmp crate with a path dep on vault-core).
- Baseline 2026-11-17 (2 targets in parallel): ~4.7k-7.8k exec/s, no crashes in 90/120 s runs.
