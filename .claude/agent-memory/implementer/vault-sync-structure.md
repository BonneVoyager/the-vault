---
name: vault-sync-structure
description: vault-sync crate layout (package dir since 2026-10-30) after P2.1 + P3.2 backups + v1.1 attachments, state model, and gotchas (rand 0.8 pin, chmod test caveat, save-when-clean no-op, same-second snapshot suffix)
metadata:
  type: project
---

vault-sync (P2.1, 2026-10-29) modules: atomic.rs (write_atomic, tmp naming), cloud.rs (CloudHooks/NoopHooks/CloudError), error.rs (SyncError), event.rs (SyncEvent), synced.rs (SyncedVault, LastWritten, LockedSummary, DOWNLOAD_TIMEOUT). Phase-3 seams: `emit()` broadcast helper. P3.3 added watch.rs + synced/reconcile.rs (see [[notify-watcher]]); state flags pending_conflicts, rewrite_on_unlock, key_mismatch, save_blocked, locked_fallback (see [[notify-watcher]]). All unlock paths go through `open_with` -> install -> after_unlock.

P3.2 (2026-10-29) added backup.rs: hand-rolled UTC stamp (Hinnant civil_from_days, no time/jiff dep), filename parse (`<name>-<stamp>[-N].vault`, `conflict-<stamp>-<orig>`), pure `retain(infos, now, mult)` with calendar buckets (UTC day, Monday week, month) per age tier, `write_snapshot` (NoReplace, `-2`,`-3` on same-second collision), `apply_retention` (never deletes unparsed names or the just-written file). Since P3.3 round 2, only `BackupKind::Snapshot` rotates; `Unsaved` (`<name>-<stamp>-unsaved[-N].vault`) and `Conflict` files are always kept (user-managed, 03 §6 never delete a conflict copy). The P3.2 brief said conflicts rotate; the reviewer overruled that. SyncedVault fields: backup_enabled, retention_multiplier, first_save_after_unlock (set in install/create/restore), last_item_count (live items, set at unlock). `SyncError::ForeignVault{expected,found}` for restore of another vault_id.

State model: `locked: LockedVault` = last on-disk bytes (re-parsed on every save); `unlocked: Option<UnlockedVault>`. Unlock always starts from `locked`; unlock while already unlocked verifies credential but keeps in-memory edits.

Gotchas:
- atomic.rs `write_atomic(path, bytes, Mode)`: Replace = rename (save); NoReplace = hard_link + unlink tmp (create, no clobber race). TmpGuard drop-removes tmp unless defused. On non-AlreadyExists link errors (exFAT/SMB) it warns and falls back to exists-check + rename; link fn is injectable via `write_atomic_with` for tests.
- `LastWritten.mtime` is Option; hash is the primary echo key; stat failure after write is only a warn.
- Use rand 0.8 (not 0.9/0.10) to share rand_core with vault-core / chacha20poly1305 0.10.
- secrecy/uuid come via vault_core re-exports; no direct dep needed.
- chmod 0500 on the dir makes save fail at tmp creation, not rename; real rename-failure test is in atomic.rs (rename file over a non-empty dir).
- Two snapshots in one test run land in the same second: any new snapshot path must handle NoReplace AlreadyExists (suffix), and sorting ties use `seq_of(path)`.
- To test a policy trigger in isolation, keep a fresh own snapshot present (else the hourly rule fires anyway); chmod 0500 on the backups dir fails snapshot writes while listing still works. `BackupInfo.kind` (Snapshot/Unsaved/Conflict) is authoritative; seq is only the same-second tie-break. The hourly check counts only Snapshot.
- Every read of the primary or a backup goes through `hooks.ensure_downloaded` first (03 §7); reviewers check this.
- clippy (1.99) flags `sort_by(|a,b| b.cmp(a))` -> use `sort_by_key(|x| Reverse(..))`.
- vault-core/src/vault.rs is edited concurrently by other agents; rely on public API only.
- Deliberate deviations from 03 §8: `open` takes device_id; `edit` returns Result; save on a clean vault is a no-op.

Attachments (v1.1, 2026-10-29): src/attachments.rs (dir/blob paths, `prune`, `AttachmentReader`, `AttachmentState`) + src/synced/attachments.rs (SyncedVault methods). `atomic::write_atomic_stream(path, mode, fill)` streams into the tmp. Reader runs core `attachment::open` on a helper thread feeding a bounded(1) channel of Zeroizing chunks (core only offers push-style open). Orphan prune runs only after a save that WROTE (clean save skips: memory may lag disk). Age = now - max(mtime, ctime) (cloud providers keep the peer's mtime). Setting mtime refreshes ctime, so tests cannot age files; they use hidden `set_prune_clock_offset_for_tests`. With an offset, a peer's blob whose ref is not yet saved is legitimately pruned, so apply offsets only after all refs are saved. Gotchas: core `seal(vault_id, ref, plain, out)` takes the ref by value and returns it on success (one ref, one seal); seal/open have no format_version arg (blob AAD version is a core constant); removals propagate via `Item.removed_attachments` tombstones; vault-app matches `SyncEvent` exhaustively (new variants break it).

Package layout (2026-10-30, 03 §1): a vault is a dir `<name>.vault/` with `vault.bin`, `attachments/`, `backups/`. All path helpers live in src/package.rs (`vault_file`, `attachments_dir`, `backups_dir`, `vault_name`, `ensure_dir`, `create_new_dir`; pub `VAULT_FILE_NAME`). `SyncedVault.path` = package, `.file` = vault.bin (`vault_file()` getter); every primary read/write/fingerprint/pin uses `.file`. `open` on a regular file -> `SyncError::NotAPackage` (no migration). Snapshots `<name>-<stamp>[-unsaved][-N].vault.bin`; conflicts are whole package dirs moved to `backups/conflict-<stamp>-<orig>/` (listed as Conflict, size = inner vault.bin; `restore_from` accepts a dir and reads its vault.bin). Absorption copies missing `attachments/*.bin` (NoReplace) BEFORE merge+save, then moves the package. Orphan prune also runs once after unlock (open_with) only if the primary read OK, not dirty, no key_mismatch/save_blocked. Tests: hardening/watch helpers return the vault.bin path and open via `pkg(&path)`/parent; siblings planted as packages (hidden staging dir + rename). Core `Item::new(title, device, now)` since ItemKind removal.

**Why:** future phase-3 work (watcher, backups, conflicts) builds on these seams.
**How to apply:** extend synced.rs rather than restructure; keep `locked` in sync with disk when adding watcher reloads.
