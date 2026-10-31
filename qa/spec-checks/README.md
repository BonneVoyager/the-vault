# spec-checks

Independent checks written from `specs/` and the README only, before reading the source. Outside
the workspace (own `[workspace]`). Every test names the spec sentence it checks. Keep every
existing check; add new ones. This is the regression ledger.

```sh
cargo build -p vault-cli                       # from the repo root, for the CLI checks
cd qa/spec-checks
cargo build --bins                             # child-process harnesses for hostile inputs
cargo test --no-fail-fast
./cli/run_all.sh                               # black-box CLI against target/debug/vault
```

- `src/lib.rs`: an independent decoder and independent crypto (Argon2id, HKDF, XChaCha20-Poly1305 with the spec AADs), sync helpers, and a child-process runner with time and RSS limits.
- `src/bin/`: `open_file`, `open_kdbx` and `open_1pux` harnesses, so aborts or OOM in hostile-input cases are observable.
- `tests/`: `format`, `corruption`, `keys`, `merge`, `sync`, `sync_edge`, `sync_cloud`, `attachments`, `retention`, `totp_gen`, `import`, `modes`, `cli_bridge`, and since 2026-10-31 `field_ids`, `merge_ids`, `upgrade`.
- `src/lib.rs` also has an independent file writer (`build_file`) and UUIDv5 (`uuid5`, `derived_field_id`) for hand-made version 1 and version 2 files.
- 2026-10-31 port to format version 2: by-name `set_field` calls became `set_field_named`; rebuilt files keep the source file's version; "newer version" simulations use version 3; `snap_item` includes field ids, `removed_fields`, `created_at` and icons.
- Temp files go under `tmp/` (git-ignored) and are removed by each test.

A passing check shows the behaviour on those inputs only. It is not a proof.
