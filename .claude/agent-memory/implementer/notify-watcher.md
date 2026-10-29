---
name: notify-watcher
description: vault-sync watcher design (P3.3) and notify 8.2 / notify-debouncer-full 0.7 quirks on macOS FSEvents
metadata:
  type: project
---

Design (P3.3, 2026-10-29): `watch.rs` owns the Debouncer; its handler only classifies paths into `WatchSignal`s on a crossbeam channel. `SyncedVault::poll()` (src/synced/reconcile.rs, a child module so it sees private fields) runs 03 §3/§6 on the caller's thread. Watching is explicit (`start_watching`/`stop_watching`), not automatic in open/create. Vault key is exported per use, not cached (an edit can `rotate_vault_key`).

Quirks:
- notify-debouncer-full 0.7.0 uses notify 8.2 (0.6 also does); 0.8 and notify 9 were only RCs in Oct 2026. Debouncer re-exports `notify`; Drop stops its threads.
- FSEvents reports resolved paths (/private/var/... for tempdir /var/...): match the event's parent against both the given and the canonicalized dir.
- Spec §3 step 6c ("save only if ours changed") does not converge when ours strictly dominates the disk copy (another device overwrote our later delete). Also save when `theirs.merge_from(ours).changed()`. The delete-after-edit §9 test catches this.
- Save/unlock invariants after the P3.3 review (2026-10-29): `save` reconciles the primary (stat+hash vs last_written) before writing even without a watcher; refuses on key_mismatch / save_blocked (NewerVersion, ForeignVault) BEFORE the clean early-return; `lock` writes an encrypted `<name>-<ts>-unsaved.vault` (BackupKind::Unsaved) when saving is impossible. Unverified `locked` replacements keep `locked_fallback` for tampered-file fallback. Only the password path resolves KeyMismatch (emits KeyRotatedOnDisk; rollback to a pre-rotation file is undetectable). `lock` snapshots whenever key_mismatch or save_blocked (dirty or not); `dirty_from_corrupt` carries a pending rewrite across lock into rewrite_on_unlock. Reviewers hunt for "state X lets autosave overwrite disk" and "lock drops edits" holes.
- Helpers: `SyncedVault::read_parsed(path)` (synced.rs) = ensure_downloaded→read→parse, Ok(None) if missing; use it for any new read of the primary/copies/backups. Sibling ForeignVault/Error reports are deduped per (path, hash, kind) in `sibling_reports`. Debouncer Drop only sets a stop flag (no join). Scan existing siblings AFTER `watch()` starts, never before (gap).
- vault-app's settings screen matches `BackupKind` exhaustively: adding a variant breaks it (reuse `Unsaved`; it also holds raw bytes of an unparseable primary kept by restore_from).
- `UnlockedVault::serialize` uses fresh nonces: two serializations of the same vault never hash equal. Compare content by opening with the key and checking `copy.merge_from(ours)` is unchanged (+ slots equal).
- `save` propagates primary read errors (cloud timeout/IO) from the pre-merge; poll/unlock report them as events instead (`reconcile_primary_reporting`). restore_from refuses over a newer-format primary and calls after_unlock.
- `merge_in` returns need-write instead of calling save (save calls reconcile_primary; avoid recursion).
- Crafting test files: `vault_core::format::VaultFile` parse/to_bytes, flip `items[0].ct[0]` for a tampered first record (unlock_with_key says WrongPassword); bytes[4..6] BE u16 = format version.
- Tests: plant files via hidden tmp + rename; wait with deadline loops around poll(); the watch suite takes ~3 s and was 15/15 stable.

**Why:** later phase-3/4 work (app tick, iCloud hooks) builds on poll().
**How to apply:** keep the watcher thread free of vault state; add new reactions in reconcile.rs. See [[vault-sync-structure]].
