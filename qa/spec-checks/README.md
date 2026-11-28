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
- 2026-11-08 additions: `field_icon` (01 §4/§9 `Field.icon`: fixture shape, writer omits none,
  `""`/`Some("")` = none, hostile types Malformed, unknown names kept through edits, merge, key
  operations and trash, icon-only restamp, whole-field merge with 2 and 3 devices, cloned-device
  tie, `Some("")` settling, version 1 + `upgrade_format`, no carry through CSV/1PUX/KDBX, cut and
  bit-flip sweeps, both conflict-copy shapes, CLI get/edit/export/rm/upgrade/sync, field reorder
  propagation), `before_write` (03 §2 hook: dirty vs clean saves, lock before the Unsaved backup,
  never while locked or on `restore_from`, after the pre-write merge, merge write-backs and
  absorption, expired trash from a peer never reaching disk, before the 64 MiB size check, pre-hook
  `Merged` reports, survives lock/unlock), `src/bin/field_icons` and a `run_all.sh` field-icon
  section (fixture vault through the CLI, 12 concurrent field adds).
- 2026-11-15 additions: `field_order` (03 §5 "Field order": winner's order then the loser's
  extras in the loser's order, reorder restamps the item but no field, later edit elsewhere wins
  the order, device-id and cloned-device payload ties, three devices with markers, reorder vs
  delete, markers filtering loser extras, the merge laws on random scripts with shuffles and
  moves, two handles on one folder, both conflict-copy shapes via `vault sync`, and the 03 §5
  concurrent CLI edit rules: same attribute keeps one, different attributes all survive),
  `host_facts` (04 §1b `os_version`/`model_identifier` against `sw_vers`/`sysctl`, thread safety,
  no identity; 04 §5d `launched_as_login_item` false off the main thread). `Cargo.toml` gains a
  macOS-only path dependency on `vault-macos` for these plain functions; the rest of vault-macos
  stays code read only. `run_all.sh` gains concurrent attribute edits (3 reps), concurrent
  `--tag`, and a docs/help.md shortcut table vs 05 §4 consistency check.
- 2026-11-17 additions: `lock_hook` (03 §2 save-lock wait and the `test-support` hook
  `shorten_lock_timeout_for_tests`: 10 s default, lowers, "can only lower it" both above the
  default and after a lower call, zero, 17 concurrent callers keep the minimum, the production
  CLI waits 10 s with override-looking env vars set, and the shipping feature graph of vault-app
  and vault-cli has no `test-support`; every library case runs in its own `src/bin/lock_hook`
  child because the override is process-wide, and the lock is held by a perl `flock`),
  `icon_catalog` (01 §4 item and field icons with any strings after the 2026-11-16 Lucide catalog
  change: round trip with odd kinds/identifiers/colours, two- and three-device merge,
  cloned-device ties, the legacy kind "logo" from `v1-icon.vault` through edits and merges, a
  65 MiB icon refused by the 64 MiB save cap, every fixture opens and round-trips, the CLI
  `--icon symbol:<name>[:#RRGGBB]` storing odd identifiers verbatim and refusing bad shapes,
  hostile icons from a peer through get/list/export/edit/sync of both conflict-copy shapes, and
  the CLI on the icon fixture incl. `upgrade`), `src/bin/item_icons` (item icons via the
  independent decoder), and a `run_all.sh` section for the held-lock wait, `--icon` identifiers,
  control bytes in an icon value and six concurrent `--icon` edits.
- 2026-11-21 additions: `realign_1121` (sentences the 2026-11-19 realignment now asserts about
  core and sync: version 0 = `UnsupportedVersion(0)`, empty body / misplaced or doubled manifest =
  `Malformed`, KDF range boundaries at parse and at creation, passkey slot kept opaque,
  `Tampered(Header|ItemCount)` never produced over header flips and every cut, unknown keys kept or
  dropped per struct (01 §9), Argon2 once per unlock with 8 password slots, mutation stamps past
  `previous` and `deleted_at`, generator clamp and lowercase fallback, pool sizes 83/88 vs the
  observed alphabet, the 05 §2.1 bucket sentence, zxcvbn claims, CSV injection guard round trip,
  import `created_at`, exact KDBX KDF bounds, `unlock_with_key` error mapping per record and its
  vault-sync event, `open`'s shared lock, `ForeignVault` once per sibling, per-file conflict names
  incl. a forced same-second clash, every backup openable, named fixtures), `exports_1119` (02 "Also
  exported" names and constants, isolated so a missing name fails only that file), and a
  `run_all.sh` section (no-op and failing `vault sync`, `list` waiting on a held save lock, a
  version-0 file, dependency lists in 02/03/04 vs `cargo tree`, `docs/help.md` and specs vs the
  removed Move…).
- 2026-11-21b additions: `conflicts_1121` (03 §6 step 1 and the §8 `UnreadableConflict` sentence
  dated 2026-11-21: random-bytes, truncated, version 0/3/0xFFFF per-file copies and sibling
  packages each reported once and left in place; same bytes under a new mtime silent, other bytes
  reported again; reported again after absorption, disappearance, lock/unlock and stop/start
  watching; two paths with the same bytes; non-candidate paths silent; a copy whose download
  fails waits (`CloudUnavailable`); `ForeignVault`, `WaitingForBlobs` and `UnreadableConflict`
  side by side; a sibling that is unreadable, then waiting, then absorbed; a sibling directory
  before its `vault.bin`; restore with an unreadable copy present; 03 §3 version 0 vs newer
  primary, unlocked and locked; 03 §8 `restore_from` over a version-0 and a version-3 primary;
  oversize and symlinked copies recorded; 40 copies drain; D-1 symlink/FIFO per-file copies and
  symlinked sibling packages not silent; `SaveBlocked` counts across lock/unlock; 05 §2.3 danger
  pill contrast arithmetic; 01 §4 fixture stamp sentence), and a `run_all.sh` 2026-11-21b section
  (`vault sync` with unreadable copies of both shapes and all versions: rc 1, named, kept,
  primary untouched; readable beside unreadable; 20 copies; concurrent adds and syncs; symlink,
  FIFO and symlinked-sibling copies; a 65 MiB copy; `docs/help.md` ⌥ sentence).
- 2026-11-22 additions: `backups_1122` (03 §4 retention at 0.5/1/2/4x against the 05 Settings
  days and hint, multiplier clamp/NaN/±inf/-0 equivalence, same-second `-N` suffixes, hostile and
  future-dated snapshot names, the hourly policy, backups disabled vs `backup_now`/pre-restore/
  Unsaved-on-lock, names and modes; `restore_from` on every listed kind, while dirty (INFO), a
  cut-and-bit-flip sweep of the backup, special entries, three handles converging after a restore,
  across a password change; 03 §1.1 trash expiry vs a restored snapshot with the app's sweep hook
  and a peer; `save_blocked()` across lock/unlock for newer and foreign primaries, locked and
  unlocked; 03 §6 special conflict entries (socket, directory, dangling/looping links, links to
  /dev/zero and a FIFO, FIFO sibling, sibling whose vault.bin is a FIFO/directory/link) reported
  once and left, replaced by a regular copy, re-reported after lock/unlock, a sibling with a
  symlinked `attachments/`; `delete_backup` on links; `backups()` and the viewer's no-follow
  reader with FIFOs and links; a symlinked `backups/` on the policy snapshot; a vault named
  `conflict` (bk10/bk11, added after the source read)), and a `run_all.sh` 2026-11-22 section
  (`vault sync` with each special entry, 10 concurrent adds vs backups openable and 0600, a
  symlinked `backups/` reported by `add`).
- 2026-11-27 additions (format 3 and the 2026-11-26 security-review waves): `v3_format_1127`
  (an independent v3 writer with record-level unknown keys; SHA-256 of the raw header bytes; the
  01 §4 tamper map on both unlock paths; duplicate header keys; relabels to 1/2/4/0xFFFF; entry
  shapes incl. a three-element entry in a v2 file; record order; every-bit flips on the key path
  and header flips on the password path; every cut of v3 files; `upgrade_format` no-op on v3 and
  v2 → 3 dropping opaque slots; hostile KDF in a v3 header), `merge_g6_1127` (02 guarantee 6 per
  merge over 60 random 2-/3-device scripts with a coarse shared clock, a per-device pair ledger,
  equal-stamp conflicts in both directions, the `created_at` carry, the 03 §5 header merge guard
  with unstamped v3 vs stamped v2 headers, L-02 stamp-on-save, guarantee 11), `backups_1127`
  (Unsaved fallback copies: path, modes, event, listing, restore, delete, path rules, symlinked
  vault-id folder; `repair_package` cases incl. links, FIFOs, name collisions and a newer stub;
  authenticated retention: unvalidated entries, forged-body holders, rotated-key snapshots,
  >10,000 entries), `freshness_1127` (`Freshness::of`, `on_disk_freshness`, the `Merged` event's
  `peer`, a stale primary written back), `quarantine_1127` (restore from `attachments/orphaned/`
  at unlock, `attachment_state` and `open_attachment`; copy selection by size; existing blob wins;
  symlinked `orphaned/`; fresh orphans stay), `caps_1127` (CSV/1PUX 100 000-item and 64 MiB text
  caps, 10 000 zip entries, a hand-made ZIP64 directory, a 17 MiB and a lying `export.data`, a
  KDBX gzip bomb, `below_recommended` edges, TOTP period spellings), `sync_v3_1127` (record
  unknown keys through a merge, a v2 per-file copy, a header-tampered v3 sibling, a v2 rollback and
  a relabelled primary under an unlocked device), `src/lib.rs` `w1127` (writer, slot re-wrap, fast
  record decryptor), and a `run_all.sh` 2026-11-27 section (reveal escaping against `vault get
  --help` incl. every Cf code point, C1/bidi titles, the `VAULT_DEV_KDF` gate and one-line
  warning, the TOTP period cap through `add`, `vault list`/`upgrade` on a v2 file, a planted
  `backups` file).
- Temp files go under `tmp/` (git-ignored) and are removed by each test.

A passing check shows the behaviour on those inputs only. It is not a proof.
