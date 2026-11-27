# 03 — `vault-sync`: file sync, merge, backups

Model: the vault lives at a user-chosen path. iCloud Drive, Dropbox, Google Drive, a NAS mount, and `~/Documents` are all the same thing — a directory that something else may rewrite underneath us. One code path.

Dependencies: `vault-core`, `notify` (+ `notify-debouncer-full`), `rustix` (no-replace rename, errno constants), `blake3`, `crossbeam-channel`, `rand`, `unicode-normalization`, `zeroize`, `thiserror`, `tracing`; `tempfile` is dev-only (spec aligned to code 2026-11-19). No async runtime; a dedicated thread for the watcher.

## 1. Directory layout

```
<dir>/
  <name>.vault/                     a macOS package (directory shown as one icon; UTI dev.vault.app, LSTypeIsPackage)
    vault.bin                       the vault file (format per 01, unchanged)
    attachments/<id hex>.bin        (v1.1)
    attachments/orphaned/<id hex>.bin[.<n>]   quarantined orphans (§1.1, 2026-11-26)
    backups/
      <name>-2026-10-28T14-03-11Z.vault.bin
      ...
    .lock                           advisory save lock (§2), empty
    .vault.bin.tmp-<8 hex>          transient; never left behind on clean exit
```

Decided 2026-10-30, before any real vault existed: the package replaces the former `<name>.vault` file plus `<name>.vault.attachments/` and `<name>.vault.backups/` siblings. One Finder item to drag, copy, delete or back up; cloud providers sync the files inside individually, so writes stay small. Without the app installed the package shows as a plain folder, which is intact. Conflict copies come in two shapes (§6): whole sibling packages (iCloud) and per-file copies of `vault.bin` inside the package (Dropbox, Google Drive, Syncthing). Both are absorbed and moved into `backups/`.

Every file in `backups/` is a complete, independently-openable vault file; absorbed conflict packages (§6) are directories there. Backups are encrypted; the directory is safe to sync. (spec aligned to code 2026-11-19)

### 1.1 Attachments directory

`<name>.vault/attachments/<id hex>.bin`, one immutable blob per attachment (`01` §4). Writes are atomic (tmp + fsync + rename, mode 0600) like the vault. Reads call `ensure_downloaded` first; an evicted or absent blob is reported as `AttachmentState::NotDownloaded` / `Missing`, never as an error that blocks the item. Blobs are immutable, so there is nothing to merge.

**Orphan cleanup**: after each `save` that wrote the file, and once after a successful unlock from locked (only when the primary was read, nothing is dirty and saving is not blocked), a blob whose id is referenced by no item (live or tombstoned) is moved into quarantine (see below) once it has been present locally for more than 24 h. "Present locally" is measured from `max(mtime, ctime)`: cloud providers preserve the source device's mtime, but ctime is set by the local kernel on create or rename and cannot be forged, so a peer's blob that arrives before its vault file always gets the full grace period. The same rule applies to stale tmp files (1 h). Cleanup never runs while locked. After a save, the pass runs only when the set of referenced blobs changed since the last pass or 24 h have passed (security review 2026-11-26 L-06); the unlock-time pass always runs and resets that tracking. References are judged by this device's state after the pre-save merge; a reference a peer holds only in memory does not protect its blob once the grace period has passed (the app's 2 s autosave keeps that window theoretical). Deleting an item keeps its refs on the tombstone while it is in Recently Deleted (30 days, 02 §Recently Deleted); a strip (permanent delete or the 30-day sweep) drops them, and the blob is then an orphan whose grace is measured from when it arrived, not from when it lost its last reference, so a long-trashed blob can be deleted at the very next save. Accepted (owner decision 2026-11-07, bug-hunt 2026-11-06 note): in the already-accepted recover-vs-strip race (§5), the recovered item survives but its attachments can show as Missing on the recovering device once the blob is gone; no separate grace for a just-unreferenced blob.

**Quarantine instead of deletion (owner decision 2026-11-26, security review 2026-11-26 M-02):** a stale but authentic `vault.bin` (from a provider's version history, or a provider resolving a conflict in favour of an old file) opens normally, and cleanup judged against it used to delete every blob added since, with the deletion syncing everywhere and no backup of blobs. Now:

- Cleanup never deletes a blob from `attachments/`. An orphan past the 24 h grace (`ORPHAN_GRACE`) is moved, with a no-replace rename, into `attachments/orphaned/` (0700, created on demand; the blob keeps its 0600 file) under its own name. The directory is inside the package, so it syncs and the symlink/regular-file rules of §1 apply (a symlinked `orphaned/` is refused and nothing is moved). No leading dot, so providers that skip hidden entries still sync it; the name cannot clash with a blob name. If `<id>.bin` is taken there, the lowest free `<id>.bin.<n>` (1-16) is used; past 16 the blob stays in place (logged). `SyncEvent::AttachmentsPruned(n)` now counts blobs moved into quarantine.
- **Second grace period** `QUARANTINE_GRACE` = 30 days (matching Recently Deleted): a quarantined file is deleted once it has been in quarantine longer than that, measured like the first grace from `max(mtime, ctime)`; the move refreshes ctime, so the age runs from the move on this device (from arrival on a peer). Each pass restores first, then expires, then quarantines, so nothing is quarantined and deleted in one pass.
- **Restore:** a quarantined blob whose id the unlocked vault references (live or tombstoned) is moved back (no-replace; a blob already in `attachments/` wins and the quarantined copy expires) at every cleanup pass, after every unlock (always, also when the pass below is skipped), after a merge that changed our state, after a key re-adoption, after `restore_from`, and by `attachment_state` / `open_attachment` before they would report the blob missing. Per id the lowest copy number whose size equals the sealed length implied by the reference is taken; a wrong-sized copy is never restored. While locked nothing is restored (references unknown) and a quarantined blob reads as `Missing`.
- **Skip rule:** the unlock-time pass (not the restore) is skipped when the `vault.bin` being opened replaced, unverified, the last version this process verified, i.e. it changed while locked (`locked_fallback` is set). The next save, or the next unlock over the same now-verified file, runs cleanup as before. A fresh process has verified nothing and runs the pass on its first unlock; quarantine covers that case. Residual: a rollback planted while the app is closed still quarantines on the first unlock, and any later save quarantines against the adopted state; the blobs stay recoverable for 30 days by restoring the newest snapshot (or by a peer's newer state merging in). A local freshness anchor (review I-02) remains future work.

**Recently Deleted and backups (owner decision 2026-11-03):** snapshots are byte copies of the vault file, so an item in the trash is inside any snapshot taken during its window and comes back *into the trash* when that snapshot is restored; after the window it is stripped from the file and absent from later snapshots. Snapshots are not scrubbed.

**Limitation (owner decision 2026-10-29): attachments are not backed up.** Snapshots copy only the vault file. Restoring a backup may yield references whose blobs are gone; those show as `Missing`. Blobs orphaned within the last 30 days come back from quarantine on restore (2026-11-26). Attachment size cap 100 MB per file.

Provider label (2026-10-31, pure classifier in vault-sync `cloud`): under `~/Library/Mobile Documents/` is iCloud Drive. Under `~/Library/CloudStorage/<Prefix>-…`, the provider is the segment right after CloudStorage, cut at its first `-`: Dropbox, OneDrive, GoogleDrive shown as "Google Drive", Box, otherwise the raw prefix. `~/Dropbox` or `~/Dropbox (<team>)` is Dropbox. Otherwise iCloud Drive if `NSURLIsUbiquitousItemKey` is true, else "Local folder". Path rules come first because File Provider folders also report ubiquitous.

## 2. Writing — `SyncedVault::save`

```
1. bytes = vault.serialize()
2. write bytes to <name>.vault/.vault.bin.tmp-<rand>   (O_CREAT|O_EXCL, mode 0600)
3. fsync(tmp)
4. bind-check, then rename(tmp, <name>.vault/vault.bin)   atomic on APFS / HFS+ / ext4
   (2026-11-06, external review D-2): the tmp handle stays open; lstat(tmp path) must match the
   handle's (dev, ino) or nothing is renamed (`UnsafePackageEntry`). When a primary exists, the
   rename replaces it only if its (dev, ino, size, mtime) still equal what the pre-write merge read
   (`Mode::ReplaceIf`); when only (dev, ino) differ, a (size, blake3) match of the current bytes
   counts as unchanged (SMB/FUSE mounts and iCloud same-bytes rewrites renumber inodes). A mismatch
   is `PrimaryChangedDuringSave`: `save` re-reads, re-merges and tries again, up to 3 attempts in total, then returns
   the error with the vault still dirty; the app treats it like a busy lock (friendly message, one
   scheduled retry). Residual: the microseconds between the checks and rename(2); macOS has no
   compare-and-rename.
5. fsync(package dir)                              ignore ENOTSUP/EOPNOTSUPP/EINVAL/ENOSYS (unsupported); any other error → Err, vault stays dirty
6. record (mtime, ctime, inode, size, blake3(bytes)) as `last_written`   (V-05: mtime+size alone misses a same-size write within one timestamp tick on coarse filesystems)
7. maybe_backup(bytes)                             §4
```

**Blob publication is authenticated (2026-11-06, D-6):** a blob copied from a conflict package (with or without a `vault.bin`) is published only if its length equals the sealed size computed from the reference and every chunk authenticates under the reference's key while it is copied (plaintext goes to a sink, never retained); a bad blob is skipped with a warning and nothing is written. An existing blob is never replaced. Blobs published before this date are not re-verified; the reader's AEAD check and orphan cleanup remain the backstop.

**Watcher bounds (2026-11-06, D-11):** the signal channel is bounded (1024, non-blocking sends); a full channel drops the signal and sets a rescan flag honoured by the next poll. The candidate queue is deduplicated and capped at 256 (overflow → rescan flag and one log warning per episode; no `SyncEvent`, since nothing needs the user's attention). A poll processes at most 8 candidates; the rest wait for the next poll, so one-shot callers (`vault sync`) loop on `poll()` until it returns 0. Directory scans page, so every candidate is eventually seen.

**Before-write hook (2026-11-07):** `SyncedVault::set_before_write(Option<BeforeWrite>)` with `BeforeWrite = Box<dyn FnMut(&mut UnlockedVault) -> bool + Send>`. vault-sync calls it on the unlocked in-memory vault right before every write that serialises it: inside each dirty `save` attempt after the pre-write merge and before the size check and serialisation (app saves, merge write-backs, conflict absorption, the rewrite after unlock), and in `lock` before the Unsaved backup. It never runs on reads or polls with nothing to write, on a clean save, while locked, on `create`, or on `restore_from` (which writes the backup bytes as they are). The hook stamps its own changes through core APIs and returns whether it changed anything; a change is carried by the write that follows and does not mark the vault dirty; `SyncEvent::Merged` reports describe the pre-hook state. Policy stays with the caller: the app installs the 30-day Recently Deleted sweep (`expire_deleted`, guarded by a due check so a clean vault is never restamped) at open/create and again after unlock, so content a peer's file brings back past its window is stripped before vault-sync's own write-back reaches disk (closes the bug-hunt 2026-11-06 note).

**Not following links (2026-11-06, D-1):** every file the package opens (`.lock`, `vault.bin`, backups, blobs, conflict-copy sources) is opened with `O_NOFOLLOW` and must be a regular file after `fstat`; a symlink or special file is `UnsafePackageEntry`, never a silent fallback (a symlinked `.lock` must not degrade to the no-lock path). `backups/` and `attachments/` must not be symlinks. The package directory itself is resolved once at `open` (documented). Directory components are still path-checked, so a same-uid process that swaps a directory between check and use can race; that is the accepted residual. The backup viewer reads backups through the same no-follow reader (`vault_sync::read_package_entry_capped`); a conflict package in `backups/` whose `vault.bin` is a symlink is not listed (bug-hunt L3, 2026-11-06).

When a vault whose header has never been stamped (`slots_modified_at` absent) is unlocked through a key slot (`unlock_with_kek`, Touch ID), saving is refused with `SaveBlocked::PasswordUnlockRequired` (event `SyncEvent::SaveBlocked`, error `SyncError::SaveBlocked`, also reported by `save_blocked()`) until one unlock or verification with the master password, or a restore; the first save after that stamps the header (security review 2026-11-26 L-02 follow-up). Lock still keeps unsaved edits as an Unsaved backup, and orphan cleanup does not run at that unlock. Each directory pass on the save path (`backups/`, `attachments/`, the quarantine folder, the stale-tmp scan) reads at most 10,000 entries (security review 2026-11-26 L-06); entries beyond that are skipped for that pass with a path-only warning, and a partial listing never deletes more than a full one would. A dirty `save` holds an exclusive advisory lock on `<name>.vault/.lock` (flock) for its whole duration (pre-write merge read through rename, directory fsync, backup, orphan and tmp prune), and `open` takes a shared lock around its read of `vault.bin` (spec aligned to code 2026-11-19), so two processes (the app and the CLI, or two CLI commands) cannot interleave a read-modify-write and lose items (V-02). The lock wait is 10 s (`SaveLockTimeout`, nothing written); test builds may shorten it process-wide through the hidden, `test-support`-gated `shorten_lock_timeout_for_tests`, which can only lower it, and production code has no override. On volumes that do not support locking (ENOTSUP/ENOLCK) or where the lock file cannot be created for permission reasons, the save proceeds without the lock; concurrent writers are then unprotected (accepted). "Locking unsupported" warns once per process; a lock file that cannot be opened for permission reasons warns on every save (spec aligned to code 2026-11-19). Step 5 ignores only ENOTSUP/EOPNOTSUPP/EINVAL/ENOSYS from the directory fsync; any other error is surfaced and the vault stays dirty (spec aligned to code 2026-11-19). A native no-replace rename (`renameatx_np(RENAME_EXCL)` via `rustix`) is used for backups, for blobs copied from a conflict package and for quarantine moves in and out of `attachments/orphaned/` (2026-11-26), with the hard-link fallback only where that is unsupported; `add_attachment` writes its new blob with a plain atomic replace, as ids are random (spec aligned to code 2026-11-19). Reads of `vault.bin` are capped (64 MiB) and refuse larger files with a typed error before parsing. Writes are capped the same way (bug-hunt M1, 2026-11-06): a save, restore or backup whose sealed bytes exceed 64 MiB is refused with `VaultTooLarge { bytes, cap }` before any temp file is written; the file on disk is unchanged and the in-memory vault stays dirty; merge write-backs and conflict absorption are refused the same way and never mark the primary corrupt. A lock whose unsaved state exceeds the cap writes no Unsaved copy (`LockOutcome::Unpreserved`). The app shows the refusal as a persistent warning and does not retry it; the editor caps each field at 1 MiB (05 §2.3) so users do not reach it. An oversized `vault.bin` written by an older build is still treated as corrupt (accepted). Never write in place. Never truncate-then-write. If step 4 fails, delete the tmp and surface the error; the old file is intact.

## 3. Watching and reacting to external changes

Watcher: one `notify` recursive watch on the package's PARENT directory with no initial tree scan, debounced 500 ms (a second watch would restart the FSEvents stream). Classification: the package dir or `<name>.vault/vault.bin` → primary changed; `<name>.vault/attachments/**`, `backups/**` and tmp files → ignored; sibling `X.vault/` packages, `X.vault/vault.bin`, `X.vault/attachments/*` (a late blob re-triggers a deferred package move), and `<name>.vault/vault*.bin` files other than `vault.bin` → conflict candidates (§6); deeper paths ignored. Names are compared normalisation-insensitively (each component folded to NFC on both sides, including the stored package and parent paths; 2026-11-01) because providers may deliver NFD spellings; nothing is renamed on disk, and filesystem operations always use the spelling the event or caller supplied. Accepted edge: on a volume that keeps NFC and NFD names as distinct files, a sibling that differs only by form is treated as our own package.

On a debounced event for `<name>.vault/vault.bin`:

```
1. stat the file. If (mtime, ctime, inode, size) == last_written → ignore (our own write echoing back).
2. read bytes. If blake3(bytes) == last_written.hash → ignore.
3. parse → LockedVault. If parse fails → emit SyncEvent::CorruptOnDisk, do NOT overwrite, keep in-memory state.
4. If vault_id != ours → emit SyncEvent::ForeignVault, ignore.
5. If app is locked: emit SyncEvent::ChangedWhileLocked; on next unlock, unlock the on-disk version (it's authoritative while we hold nothing dirty).
6. If app is unlocked:
   a. unlock on-disk copy with cached vault_key (LockedVault::unlock_with_key, core exposes this for sync only, behind a `sync` feature)
   b. report = ours.merge_from(&theirs)
   c. if report changed ours → save()   (which writes the merged result back; the other device will merge it idempotently)
   d. emit SyncEvent::Merged(report)
   e. if ours has anything the on-disk copy lacks (an item, a newer field, a tombstone) → save() as well. Without this write-back two devices never converge when only one side changed. Side effect: unsaved edits can reach disk before the autosave timer.
```

Before every `save`, re-read the primary and merge it in (pre-write merge), so a save can never clobber a change that landed between the last watcher event and now. If the on-disk file has a newer `FORMAT_VERSION` (strictly above ours; version 0 or any other unsupported value is corruption and takes the step-3 corruption path, bug hunt 2026-11-21 L3) or a different `vault_id`, the save is refused with `SyncEvent::SaveBlocked{NewerVersion | ForeignVault}` and the in-memory state is kept.

Merge is idempotent and commutative, so a ping-pong between two devices converges in one round trip each.

While the app holds unsaved edits (dirty, before `save`), step 6 still runs — the merge brings in the external change under the user's uncommitted edit, and the next `save` writes both. There is no "discard your changes" dialog.

## 4. Backups — `maybe_backup`

Policy, evaluated on every `save`:

- Take a snapshot if no snapshot exists newer than **1 hour**, or if the item count decreased, or if this is the first save after unlock.
- Backups are not trusted by name (security review 2026-11-26 L-04): an entry counts as a snapshot only if its prefix and plaintext header (at most 256 KiB read, no symlink followed, nothing decrypted) parse as a supported vault with this vault's id (`BackupInfo::validated`; cloud-only files are not downloaded to check). Only validated snapshots take a retention slot or satisfy the 1-hour rule (at most 64 headers checked per save); unvalidated entries are never deleted and are listed after every validated one. Deleting a snapshot requires every snapshot that displaces it to authenticate fully under the current vault key (at most 512 MiB read per pass, results memoised per file and stamp for the session; a holder that fails, an exhausted budget or a locked vault means nothing is deleted this pass); the listing, the restore picker and the 1-hour rule use only the header check. Snapshots sealed under a since-rotated key therefore stay listed and restorable with the password but are never pruned, bounded by the retention set at rotation time (about a hundred files). A copied header with a forged body lists as a backup and fails at restore. When `backups/` holds more than 10,000 entries, retention is skipped for that pass. Residual: an authentic older copy of this vault under a newer name, or a copied-header plant, holds off hourly snapshots for its hour.
- Snapshot = copy of the exact bytes just written, named `<name>-<UTC ISO8601 with - instead of :>.vault.bin` inside `backups/` (`-2`, `-3` suffixes within the same second; `-unsaved` for Unsaved backups).
- Local fallback for Unsaved copies (security review 2026-11-26 L-05, owner decision B, 2026-11-27): the caller may give `set_fallback_dir(Some(dir))` a folder outside the sync location (the app passes `~/Library/Application Support/<bundle id>/unsaved`; the CLI sets none). When the Unsaved write at lock fails for any reason (a planted plain file or symlink named `backups`, a full or failing disk), the sealed copy is written instead to `<dir>/<vault_id>/<name>-<stamp>-unsaved.vault.bin` (folders 0700, a symlinked vault-id folder refused, file 0600), `BackupTaken` is emitted and the outcome is `Snapshotted(path)`; only when that also fails is it `Unpreserved` with the package's error. `backups()` lists those copies with the package's (kind `Unsaved`, header-checked like the rest), `restore_from` and `delete_backup` accept them (the path's parent must be exactly `backups/` or `<dir>/<vault_id>/` with no symlink on the way; anything else is `NotABackup`), and retention never prunes them; growth is bounded by the covering rule (a new copy only when no existing Unsaved copy already holds the edits). While `backups` is a planted entry, `backups()` returns `UnsafePackageDir`, saves that need a snapshot and every restore refuse with it, and the way out is `repair_package()`: it renames a non-directory `backups` or `attachments` entry (a plain file, or a symlink of any kind, moved as the link itself) to `<name>.quarantined-<unix seconds>` (`-2`, `-3` on collision) inside the package under the save lock, never deletes, never replaces an existing entry and never touches `vault.bin` or anything else: a newer-version `vault.bin` stub is left alone and keeps blocking saves as `NewerVersion`. It returns the new paths (empty when nothing needed moving).
- Retention (run after each snapshot):
  - keep all from the last 24 h
  - keep one per day for 30 days
  - keep one per week for 12 weeks
  - keep one per month forever (cap 36)
  - delete the rest
- Settings expose: enable/disable, the retention multiplier (0.5×–4×, shown to the user as the daily tier in days: 15 / 30 / 60 / 120, 05 §Settings), and a "Back up now" button. The multiplier scales every tier: the keep-all window (24 h × m), the daily (30 d × m) and weekly (12 w × m) tiers and the monthly cap (round(36 × m)); it is a per-device setting applied over the shared `backups/` folder, so devices with different settings prune to the smaller one (2026-11-22, bug-hunt N1/N4).

Restore (phase 2 UI): open a backup read-only in a second window with the same password (layout in 05 §2.3 "Backup viewer"); user can copy items across, or "Replace current vault with this backup" (which first snapshots the current file and writes the in-memory vault, when it is dirty or its saved state is no longer on disk (key mismatch, save blocked, missing primary), to an `Unsaved` backup, as `lock` does; if that Unsaved write fails, the restore is refused and nothing changes). A restore is a local change: on a synced folder, other devices merge by the rules in §5, so anything changed after the backup was taken (edits, deletions) carries a newer stamp and wins again at the next merge; the restore only lastingly brings back what no device touched since (2026-11-22, bug-hunt N3).

## 5. Merge semantics (`vault_core::merge`)

Inputs: `ours: &mut UnlockedVault`, `theirs: &UnlockedVault`, same `vault_id` (else error).

Per item id in `ours ∪ theirs`:

| ours | theirs | result |
|---|---|---|
| absent | present | take theirs (including tombstones) |
| present | absent | keep ours |
| both, one is tombstone | — | tombstone wins **if** `deleted_at ≥ other.modified_at`; otherwise the live item wins (edit after delete resurrects) |
| both tombstones | — | whole-item last-writer-wins by `modified_at`, tie → greater `device_id`, tie → greater canonical CBOR. A stripped tombstone (02 "Recently Deleted") is restamped when stripped, so permanent deletion and 30-day expiry propagate; a recovery (live, restamped) beats any tombstone whose `deleted_at` is older than the recovery, including a strip stamped later on another device (strips do not move `deleted_at`); only a fresh `delete` after the recovery removes the item again (owner-accepted 2026-11-03: when recover and permanent delete race, the item survives). Content a merge brings back into an already-expired tombstone is stripped again by the sweep before the next save, including vault-sync's own write-backs (before-write hook, §2). |
| both live | — | field-level merge below; title, favorite, tags (as one ordered list; a reorder counts as a change) and icon are each merged by their own stamp (2026-10-31; 01 §4 per-attribute stamps): greater stamp wins, tie → greater `device_id` of the owning item, tie → greater canonical CBOR bytes of that attribute (tags as one array); `created_at` keeps the minimum; unknown extras and anything without a stamp follow whichever item has the greater `modified_at`, tie → greater `device_id` bytes, tie → item payload bytes |

Field-level merge, keyed by `field.id` (2026-10-31; never by name):

| ours | theirs | result |
|---|---|---|
| absent | present | take theirs, unless our `removed_fields` carries a marker for that id with `removed_at ≥ modified_at` |
| present | absent | keep ours, unless their `removed_fields` carries a marker for that id with `removed_at ≥ modified_at` |
| both | — | greater `modified_at` wins whole (name, kind, value, section and, since 2026-11-07, the field `icon` travel together with no per-attribute stamp, so a rename or an icon change is an edit and a newer edit by a peer that never saw the icon drops it); tie → greater `device_id` of the owning item; tie → greater canonical CBOR bytes of the field (symmetric, so both devices converge in one round; bug hunt 2026-10-31) |

**Field order** (owner decision 2026-11-08, bug hunt of that date): order has no stamp of its own. The merged list is the item winner's fields in the winner's order (the item with the greater `modified_at`, tie → greater `device_id`, tie → item payload bytes), followed by the loser's fields the winner lacks, in the loser's order. A reorder alone restamps the item (02 `update`), so it propagates when nothing else changed; a later edit of the same item on another device wins the order too and the reorder is lost. Accepted; no per-position stamps.

**Concurrent CLI edits of one item** (same decision): two processes that each read the item, change the same stamped attribute (for example `edit --tag` on both) and save, both report success and the greater stamp wins; the other change is lost. The §2 lock protects the read-modify-write of the *file*, not of an item computed before the lock. Callers that script the CLI serialise edits to one item. Edits to different fields or items survive.

`removed_fields` markers are unioned (greatest `removed_at` per id); a field edited strictly after its marker survives and the marker is dropped on both sides. Markers are never dropped by a local removal; a merge caps them at 64 by dropping, oldest first, only markers whose field neither side still holds. Accepted limit: a third device that was offline since before such a dropped marker can still bring that field back. The former "field deletion is not tracked" limit is closed. Metadata and both-tombstone ties (equal stamp and device id) are also broken by the greater canonical CBOR bytes of the item payload, so no "tie → ours" remains.

`history` is merged by union on `(value, replaced_at)`, sorted, capped to 10 newest; `removed_history` stamps are unioned (cap 10 newest) and any history entry whose `replaced_at` is in the set is dropped, so a user's deletion of a history entry survives merge. A later `set_field` producing an entry with a stamp already in the set, or already used by an existing `history` entry of that item (2026-11-15: two history-keeping fields saved with one `now` would otherwise twin and be removed together), gets the next free stamp; both lists are capped at 10, so the bump is at most 20 ms and the field and item `modified_at` move with it, inside the accepted skew envelope. A stamp that cannot be bumped (u64 max) is an error, never a spin. Merge-created conflict-loser entries keep `replaced_at = loser.modified_at` unbumped so every device converges; such twins remain removed together. Markers are keyed by stamp alone: if two devices change the same password in the same millisecond from the same base and one side deletes that history stamp before merging, the conflict-loser value is dropped with it. Accepted.

`attachments` are merged by union on `id` (sorted by `added_at`, then `id`); `removed_attachments` tombstones are unioned with the greatest `removed_at` per id, and a ref is dropped when a tombstone for its id has `removed_at ≥ added_at`. Unlike fields, an attachment removal therefore survives a merge with a device that still holds the ref. Like `removed_fields`, `removed_attachments` markers are never dropped by a local removal; a merge caps them at 64 by dropping, oldest `removed_at` first, only markers whose reference neither side still holds, so a marker outlives the cap until the peer has dropped the reference and its blob is prunable (accepted limit, as for fields: a third device offline since before such a dropped marker can bring the reference back; 2026-11-01).

Result item `modified_at = max(ours, theirs)` (restamped per §5 below when the result is new or the inputs tie). Merged item takes `device_id` of whichever side supplied the winning metadata.

**Header merge** (added 2026-10-30 after the bug hunt, V-01/V-03): the header carries `slots_modified_at`; `merge_from` takes the whole slot set, KDF parameters and `format_version` from the header that is greater by the tuple (`format_version`, `slots_modified_at`, `slots_device_id`, canonical CBOR of the slot set — the last added 2026-11-06 after an external review, D-9: two authentic divergent header writes from a cloned device id in the same millisecond otherwise never converge); equal keeps ours; a peer header without `slots_modified_at` is never adopted whatever the tuple says: two unstamped headers keep ours, an unstamped ours adopts a stamped theirs under the usual tuple, the peer's own manifest check at unlock being the authentication (security review 2026-11-26 L-02) (2026-10-31: the version ranks first because every slot AAD binds it, so a version 2 header always beats a version 1 header and an upgrade is never undone; the device id tie-break means both devices converge). When the other side wins, the in-memory vault key is replaced by theirs as well (their slots wrap their key); a later local slot change with a greater stamp wins back by LWW. A password change, slot add/remove, re-calibration or key rotation on one device therefore survives the other device's next save. The vault key is unchanged by a password change, so the other device keeps working with its cached key; a key rotation is detected as before (`KeyRotatedOnDisk`).

Timestamps are monotone per item: every write stamps `max(now, previous + 1)`, so a clock that went backwards cannot resurrect a deleted item or let an older edit win. If a merge produces an item record that differs from this side's record, and either differs from the peer's record too or the two inputs carry the same `modified_at`, the merge stamps it one past the larger input timestamp so the manifest check and the other device see the change; a result identical to the peer's record is adopted verbatim (02 guarantee 6, symmetric rule 2026-11-26 from security review M-01). N devices converge within N merge rounds; when the `removed_fields` cap fires, two devices need N + 1 = 3 rounds, since each side can apply the cap only after it has seen the peer drop the fields, and three or more need N + 2, because a pair can cap a marker while a device outside that merge still holds the field, which resurrects it once before the marker is re-learnt from a peer that kept it (2026-10-31; bound corrected 2026-11-26).

`merge_from` returns `MergeReport` and a bool-equivalent "anything changed" so `vault-sync` can skip the write when nothing moved.

Clock skew: timestamps come from each device's wall clock. If skew exceeds a few seconds, the "wrong" edit may win on a true conflict. Accepted for v1; UI shows the losing value in field history for `password` and `pin` fields (pin since 2026-11-15), so nothing is lost. Do not add vector clocks.

## 6. Conflicted copies

Cloud providers resolve simultaneous writes by creating a sibling file instead of merging. Patterns to detect (case- and normalisation-insensitive, in `<dir>` only):

- Whole-package (iCloud): `<name> 2.vault/`, `<name> 3.vault/`, … and `<name> (<host>'s conflicted copy <date>).vault/`
- Per-file (Dropbox, Google Drive, Syncthing sync the files inside the package individually): `<name>.vault/vault (<host>'s conflicted copy <date>).bin`, `<name>.vault/vault 2.bin`, …
- Generic: any such candidate whose header `vault_id` equals ours

On watcher event for a file matching the Dropbox pattern or any new `*.vault` in `<dir>`:

```
1. parse; if the candidate does not parse, carries an unsupported format version, or is not a regular file / directory (symlink, FIFO: §2 D-1 `UnsafePackageEntry`, never followed) → emit SyncEvent::UnreadableConflict(path) once (a copy first seen while locked is reported once more at the next unlock) and leave it in place (`vault sync` reports it and exits "not converged"; a copy a provider is still downloading waits via §7 instead; 2026-11-21); if vault_id != ours → emit SyncEvent::ForeignVault once per sibling and ignore (it's some other vault the user put there) (spec aligned to code 2026-11-19)
2. unlock with cached key (if locked, defer to next unlock; keep a list of pending conflict paths)
3. ours.merge_from(theirs); save()
4. whole-package: copy any attachment blobs we lack (never replacing), then move the whole package to <name>.vault/backups/conflict-<timestamp>-<original name>/ — deferred to the next event while blobs referenced by the merged items are still missing from both sides, emitting `SyncEvent::WaitingForBlobs(conflict path)` once per waiting package (never while locked; it may fire again only after the package is absorbed or gone, or after `lock`/`stop_watching`/`start_watching` reset the bookkeeping; a package still waiting at `lock` is re-checked at the next unlock even if watching was stopped meanwhile; `ConflictAbsorbed` follows when the blobs arrive; 2026-11-01); per-file: move the file to <name>.vault/backups/conflict-<timestamp>-<original name without .bin>.vault.bin (`vault 2.bin` → `conflict-…-vault 2.vault.bin`; a same-second clash inserts `-N-` after the timestamp) (spec aligned to code 2026-11-19)
5. emit SyncEvent::ConflictAbsorbed(path)
```

Never delete a conflict copy; always move it to backups.

## 7. iCloud specifics (`vault-macos` provides, `vault-sync` calls through a trait)

```rust
pub trait CloudHooks: Send + Sync {
    /// Returns true if the file is a placeholder that must be downloaded first.
    fn is_evicted(&self, path: &Path) -> bool;
    /// Request download; blocks up to `timeout`.
    fn ensure_downloaded(&self, path: &Path, timeout: Duration) -> Result<(), CloudError>;
    /// Hint to the provider that this file should never be evicted (best effort).
    fn pin(&self, path: &Path);
}
```

Default impl (non-macOS, tests): `is_evicted → false`, `ensure_downloaded → Ok`.

`vault-sync` calls `ensure_downloaded` before every read of the primary or a conflict copy, and `pin` after the first successful open. If `ensure_downloaded` times out (default 30 s) → `SyncEvent::CloudUnavailable`; the app shows a banner and retries on the next watcher event.

## 8. Public API

```rust
pub struct SyncedVault { /* path, state, watcher handle, cached key, last_written, hooks */ }

impl SyncedVault {
    pub fn create(path: &Path, password: &SecretString, kdf: KdfParams, device_id: Uuid, hooks: Arc<dyn CloudHooks>) -> Result<Self, SyncError>;
    pub fn open(path: &Path, device_id: Uuid, hooks: Arc<dyn CloudHooks>) -> Result<Self, SyncError>;  // locked
    pub fn unlock(&mut self, password: &SecretString) -> Result<(), SyncError>;
    pub fn unlock_with_kek(&mut self, slot: Uuid, kek: &SecretVec<u8>) -> Result<(), SyncError>;
    pub fn lock(&mut self) -> LockOutcome;   // zeroizes key, drops items; unsaved edits are snapshotted to an Unsaved backup first; the outcome says Clean | Snapshotted(path) | Unpreserved(error) so the app never claims edits were kept when they were not
    pub fn vault(&self) -> Option<&UnlockedVault>;
    pub fn edit<R>(&mut self, f: impl FnOnce(&mut UnlockedVault) -> R) -> Result<R, SyncError>; // marks dirty; Err when locked
    pub fn start_watching(&mut self) -> Result<(), SyncError>;                              // explicit; watcher thread + debouncer
    pub fn poll(&mut self) -> usize;                                                        // drains watcher events on the caller's thread; callers loop while it returns > 0 (§2)
    pub fn save(&mut self) -> Result<(), SyncError>;
    pub fn is_dirty(&self) -> bool;
    pub fn stop_watching(&mut self);                                                         // stops the watcher, discards queued signals, forgets WaitingForBlobs bookkeeping
    pub fn set_before_write(&mut self, hook: Option<BeforeWrite>);                           // §2 hook; survives lock/unlock
    pub fn set_backup_enabled(&mut self, enabled: bool);                                     // off stops automatic snapshots; backup_now and pre-restore still run
    pub fn set_retention_multiplier(&mut self, multiplier: f32);                             // clamped 0.5-4.0, NaN resets to 1.0
    pub fn subscribe(&self) -> crossbeam_channel::Receiver<SyncEvent>;
    pub fn backups(&self) -> Result<Vec<BackupInfo>, SyncError>;
    pub fn backup_now(&mut self) -> Result<PathBuf, SyncError>;
    pub fn restore_from(&mut self, backup: &Path, password: &SecretString) -> Result<(), SyncError>;
    pub fn delete_backup(&mut self, backup: &Path) -> Result<(), SyncError>;   // user-initiated; path must be inside backups/ (file or conflict package) or the fallback folder (§4); refuses the primary; any kind incl. Unsaved/Conflict; name match is NFC-insensitive
    pub fn set_fallback_dir(&mut self, dir: Option<PathBuf>);   // local folder outside the sync location for Unsaved copies when backups/ is unusable (§4, L-05); default None
    pub fn repair_package(&mut self) -> Result<Vec<PathBuf>, SyncError>;   // quarantine-only: renames a non-directory backups/attachments entry to <name>.quarantined-<secs>; never deletes, never touches vault.bin; returns what moved

    // attachments (v1.1) — streaming; the ref is added to / removed from the item by these calls themselves
    pub fn add_attachment(&mut self, item: Uuid, name: &str, data: impl Read, size: u64, now: Millis) -> Result<Uuid, SyncError>; // seals + writes blob, appends ref, marks dirty
    pub fn open_attachment(&self, item: Uuid, id: Uuid) -> Result<AttachmentReader, SyncError>;  // streaming decrypt; NotDownloaded / Missing
    pub fn attachment_state(&self, id: Uuid) -> AttachmentState;                                  // Present | NotDownloaded | Missing
    pub fn remove_attachment(&mut self, item: Uuid, id: Uuid, now: Millis) -> Result<(), SyncError>; // drops the ref; blob goes via orphan cleanup
}

pub enum SyncEvent {
    Merged(MergeReport),
    ChangedWhileLocked,
    ConflictAbsorbed(PathBuf),
    WaitingForBlobs(PathBuf),    // whole-package conflict merged, move into backups/ deferred for missing blobs (§6 step 4)
    UnreadableConflict(PathBuf), // a conflict candidate that does not parse or has an unsupported format version (any value, 0 included); left in place, emitted once per path and content (re-emitted when the bytes change; the same bytes re-delivered under a new mtime stay silent) until it parses, is absorbed or disappears, and again after lock/unlock or stop/start watching (bug hunt 2026-11-21 N1)
    CorruptOnDisk,
    ForeignVault,
    CloudUnavailable,
    BackupTaken(PathBuf),
    BackupDeleted(PathBuf),      // user-initiated delete_backup
    AttachmentsPruned(usize),    // orphan blobs moved into quarantine by cleanup (§1.1, 2026-11-26)
    PrimaryMissing,              // vault.bin vanished while unlocked; kept dirty, next save recreates it
    KeyMismatch,                 // on-disk file no longer opens with our cached key (password changed elsewhere; a tampered item is CorruptOnDisk, not this, since 2026-11-21); edits are kept, next unlock re-verifies
    KeyRotatedOnDisk,            // vault_key rotated elsewhere; must re-unlock with the password
    SaveBlocked(SaveBlocked),     // NewerVersion | ForeignVault; in-memory state kept; emitted once at first detection and once per refused save
    Error(String),
    BackupFailed { unsafe_dir: bool, message: String },   // a snapshot could not be written ("backup failed: <error>"); unsafe_dir = the error was UnsafePackageDir (a planted backups entry, §4 L-05): the app shows no toast and re-raises its Repair strip, the CLI prints it like Error (2026-11-27)
}

pub enum BackupKind { Snapshot, Unsaved, Conflict }

pub const DOWNLOAD_TIMEOUT: Duration;     // 30 s; how long open waits for the provider to materialise the file (§7)
pub const MAX_VAULT_FILE_SIZE: u64;       // 64 MiB read/write cap (§2)
pub const DEBOUNCE: Duration;             // 500 ms watcher debounce (§3)

// SyncError variants beyond those named above:
//   PrimaryTooLarge(PathBuf)      vault file, backup or conflict copy over MAX_VAULT_FILE_SIZE; refused before parsing
//   UnsafePackageDir(PathBuf)     attachments/ or backups/ is a symlink or not a directory
//   AttachmentTampered(Uuid)      blob failed authentication (corrupt, truncated, swapped); discard bytes already read
```

Backups carry a kind: `Snapshot` (policy in §4), `Unsaved` (taken on lock or quit while edits could not be saved), `Conflict` (absorbed conflict copy, §6). Retention prunes `Snapshot` only; `Unsaved` and `Conflict` are never pruned. `restore_from` snapshots the current file first, and before that writes the in-memory vault, when it is dirty or its saved state is no longer on disk (key mismatch, save blocked, missing primary), to an `Unsaved` backup, as `lock` does (skipped when the newest Unsaved backup already holds it; a failure there refuses the restore with that error and changes nothing, bug hunt 2026-11-22 L3); it works even when the primary no longer parses (a version-0 primary counts as unparseable and is kept as an `Unsaved` backup; only a version strictly above ours refuses the restore as `NewerVersion`, bug hunt 2026-11-21 L3).

Autosave: the app calls `save()` 2 s after the last edit (debounced) and immediately on lock, quit, and window close. `vault-sync` does not have its own timer.

## 9. Tests (all with a temp dir and the default `CloudHooks`)

- Save → file is parseable, tmp file gone, `last_written` set.
- Save twice in 1 s → one backup. Save after `item count decreased` → extra backup.
- Two `SyncedVault`s on the same path (simulating two devices): A edits field `username`, B edits field `password` on the same item, both save, both receive watcher events, both converge with both edits.
- A deletes item, B edits it later → B's edit wins after convergence. B edits earlier → delete wins.
- Drop a file named per the Dropbox pattern with our `vault_id` → absorbed, moved to backups.
- Drop a `*.vault` with a different `vault_id` → `ForeignVault`, untouched.
- Corrupt the primary on disk → `CorruptOnDisk`, in-memory state intact, next `save` rewrites a valid file.
- Retention: generate 200 synthetic snapshots over a year, run retention, assert counts per bucket.
