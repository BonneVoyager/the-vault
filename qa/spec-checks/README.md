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
cargo fmt --all -- --check                     # formatting is part of the manual check set
```

- `src/lib.rs`: an independent decoder and independent crypto (Argon2id, HKDF, XChaCha20-Poly1305 with the spec AADs), sync helpers, and a child-process runner with time and RSS limits.
- `src/bin/`: `open_file`, `open_kdbx` and `open_1pux` harnesses, so aborts or OOM in hostile-input cases are observable.
- `tests/`: `format`, `corruption`, `keys`, `merge`, `sync`, `sync_edge`, `sync_cloud`, `attachments`, `retention`, `totp_gen`, `import`, `modes`, `cli_bridge`, since 2026-10-31 `field_ids`, `merge_ids`, `upgrade`, and since 2026-11-01 `merge_laws`, `hostile_stamps`, `sync_nfc`.
- `src/lib.rs` also has an independent file writer (`build_file`) and UUIDv5 (`uuid5`, `derived_field_id`) for hand-made version 1 and version 2 files.
- 2026-10-31 port to format version 2: by-name `set_field` calls became `set_field_named`; rebuilt files keep the source file's version; "newer version" simulations use version 3; `snap_item` includes field ids, `removed_fields`, `created_at` and icons.
- 2026-11-01 additions: `merge_laws` (00 roadmap item 2 merge laws with this ledger's own seeded
  generator, decrypting every ItemPlain independently; `removed_attachments` merge-only cap),
  `hostile_stamps` (sweeps over a file with attribute stamps and attachment markers, hostile types,
  stamps at `u64::MAX`), `sync_nfc` (03 §3 NFC path comparisons, §6 case/normalisation-insensitive
  conflict names, §8 `delete_backup` paths, `WaitingForBlobs` semantics), `cli_bridge` b10-b11
  (`VAULT_DEVICE_ID`, `edit`), and `cli/run_all.sh` sections for `edit`, `sync` and concurrent editors.
- 2026-11-06 additions: `trash` (Recently Deleted: delete/recover/delete_permanently/expire_deleted,
  strip rules incl. extras from the v1-forward fixture, both-tombstone LWW and ties, recover-vs-strip
  race, backups not scrubbed, trashed attachments, two handles, a corruption sweep, CLI `rm`),
  `review_fixes` (03 §2 D-1 symlinks and FIFOs for `.lock`/`vault.bin`/conflict sources/blobs/dirs,
  64 MiB caps vs the write path, 70 MB attachments end to end, D-6 blob publication, D-11 watcher
  bounds and `vault sync` drain with 300 copies and 10 waiting packages, D-9 header tie-break,
  D-2 same-bytes inode renumbering and a tight two-handle save loop), `kdbx_hostile` (deep group
  nesting via the `open_kdbx_stack` harness, a 70 MiB KDBX within the 100 MiB limit, a 70 MiB 1PUX
  in core, KdbxCredentials vs malformed content), and a `run_all.sh` section for `sanitize_line`,
  the sync drain, a 70 MB attachment, a symlinked `.lock` and `rm`. `run_child` picks
  `target/release` when built with `--release`.
- Temp files go under `tmp/` (git-ignored) and are removed by each test.

A passing check shows the behaviour on those inputs only. It is not a proof.
