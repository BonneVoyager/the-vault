# 03 — `vault-sync`: file sync, merge, backups

Model: the vault lives at a user-chosen path. iCloud Drive, Dropbox, Google Drive, a NAS mount, and `~/Documents` are all the same thing — a directory that something else may rewrite underneath us. One code path.

Dependencies: `vault-core`, `notify` (+ `notify-debouncer-full`), `tempfile`, `fs2` or `rustix` (for `fsync`), `thiserror`, `tracing`. No async runtime; a dedicated thread for the watcher.

## 1. Directory layout

```
<dir>/
  <name>.vault/                     a macOS package (directory shown as one icon; UTI dev.vault.app, LSTypeIsPackage)
    vault.bin                       the vault file (format per 01, unchanged)
    attachments/<id hex>.bin        (v1.1)
    backups/
      <name>-2026-10-28T14-03-11Z.vault.bin
      ...
    .vault.bin.tmp-<8 hex>          transient; never left behind on clean exit
```

Decided 2026-10-30, before any real vault existed: the package replaces the former `<name>.vault` file plus `<name>.vault.attachments/` and `<name>.vault.backups/` siblings. One Finder item to drag, copy, delete or back up; cloud providers sync the files inside individually, so writes stay small. Without the app installed the package shows as a plain folder, which is intact. Conflict copies come in two shapes (§6): whole sibling packages (iCloud) and per-file copies of `vault.bin` inside the package (Dropbox, Google Drive, Syncthing). Both are absorbed and moved into `backups/`.

Everything in `.backups/` is a complete, independently-openable vault file. Backups are encrypted; the directory is safe to sync.

### 1.1 Attachments directory

`<name>.vault/attachments/<id hex>.bin`, one immutable blob per attachment (`01` §4). Writes are atomic (tmp + fsync + rename, mode 0600) like the vault. Reads call `ensure_downloaded` first; an evicted or absent blob is reported as `AttachmentState::NotDownloaded` / `Missing`, never as an error that blocks the item. Blobs are immutable, so there is nothing to merge.

**Orphan cleanup**: after each `save` that wrote the file, and once after a successful unlock from locked (only when the primary was read, nothing is dirty and saving is not blocked), a blob whose id is referenced by no item (live or tombstoned) is deleted once it has been present locally for more than 24 h. "Present locally" is measured from `max(mtime, ctime)`: cloud providers preserve the source device's mtime, but ctime is set by the local kernel on create or rename and cannot be forged, so a peer's blob that arrives before its vault file always gets the full grace period. The same rule applies to stale tmp files (1 h). Cleanup never runs while locked. References are judged by this device's state after the pre-save merge; a reference a peer holds only in memory does not protect its blob once the grace period has passed (the app's 2 s autosave keeps that window theoretical). Deleting an item keeps its refs on the tombstone until `purge_tombstones_older_than`, so the other device learns about the deletion before the blob can go.

**Limitation (owner decision 2026-10-29): attachments are not backed up.** Snapshots copy only the vault file. Restoring a backup may yield references whose blobs are gone; those show as `Missing`. Attachment size cap 100 MB per file.

Provider label (2026-10-31, pure classifier in vault-sync `cloud`): under `~/Library/Mobile Documents/` is iCloud Drive. Under `~/Library/CloudStorage/<Prefix>-…`, the provider is the segment right after CloudStorage, cut at its first `-`: Dropbox, OneDrive, GoogleDrive shown as "Google Drive", Box, otherwise the raw prefix. `~/Dropbox` or `~/Dropbox (<team>)` is Dropbox. Otherwise iCloud Drive if `NSURLIsUbiquitousItemKey` is true, else "Local folder". Path rules come first because File Provider folders also report ubiquitous.

## 2. Writing — `SyncedVault::save`

```
1. bytes = vault.serialize()
2. write bytes to <name>.vault/.vault.bin.tmp-<rand>   (O_CREAT|O_EXCL, mode 0600)
3. fsync(tmp)
4. rename(tmp, <name>.vault/vault.bin)             atomic on APFS / HFS+ / ext4
5. fsync(package dir)                              ignore ENOTSUP/EOPNOTSUPP/EINVAL/ENOSYS (unsupported); any other error → Err, vault stays dirty
6. record (mtime, ctime, inode, size, blake3(bytes)) as `last_written`   (V-05: mtime+size alone misses a same-size write within one timestamp tick on coarse filesystems)
7. maybe_backup(bytes)                             §4
```

Steps 1–7 run under an exclusive advisory lock on `<name>.vault/.lock` (flock), taken before the pre-write merge's read and released after the rename, so two processes (the app and the CLI, or two CLI commands) cannot interleave a read-modify-write and lose items (V-02). On volumes that do not support locking (ENOTSUP/ENOLCK) or where the lock file cannot be created for permission reasons, the save proceeds without the lock and logs a warning once; concurrent writers are then unprotected (accepted). Step 5 ignores only ENOTSUP/EINVAL from the directory fsync; any other error is surfaced and the vault stays dirty. Step 4 uses a native no-replace rename (`renameatx_np(RENAME_EXCL)` via `rustix`) for backups and blobs, with the hard-link fallback only where that is unsupported. Reads of `vault.bin` are capped (64 MiB) and refuse larger files with a typed error before parsing. Never write in place. Never truncate-then-write. If step 4 fails, delete the tmp and surface the error; the old file is intact.

## 3. Watching and reacting to external changes

Watcher: one `notify` recursive watch on the package's PARENT directory with no initial tree scan, debounced 500 ms (a second watch would restart the FSEvents stream). Classification: the package dir or `<name>.vault/vault.bin` → primary changed; `<name>.vault/attachments/**`, `backups/**` and tmp files → ignored; sibling `X.vault/` packages, `X.vault/vault.bin`, `X.vault/attachments/*` (a late blob re-triggers a deferred package move), and `<name>.vault/vault*.bin` files other than `vault.bin` → conflict candidates (§6); deeper paths ignored.

On a debounced event for `<name>.vault/vault.bin`:

```
1. stat the file. If (mtime, size) == last_written → ignore (our own write echoing back).
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

Before every `save`, re-read the primary and merge it in (pre-write merge), so a save can never clobber a change that landed between the last watcher event and now. If the on-disk file has a newer `FORMAT_VERSION` or a different `vault_id`, the save is refused with `SyncEvent::SaveBlocked{NewerVersion | ForeignVault}` and the in-memory state is kept.

Merge is idempotent and commutative, so a ping-pong between two devices converges in one round trip each.

While the app holds unsaved edits (dirty, before `save`), step 6 still runs — the merge brings in the external change under the user's uncommitted edit, and the next `save` writes both. There is no "discard your changes" dialog.

## 4. Backups — `maybe_backup`

Policy, evaluated on every `save`:

- Take a snapshot if no snapshot exists newer than **1 hour**, or if the item count decreased, or if this is the first save after unlock.
- Snapshot = copy of the exact bytes just written, named `<name>-<UTC ISO8601 with - instead of :>.vault.bin` inside `backups/` (`-2`, `-3` suffixes within the same second; `-unsaved` for Unsaved backups).
- Retention (run after each snapshot):
  - keep all from the last 24 h
  - keep one per day for 30 days
  - keep one per week for 12 weeks
  - keep one per month forever (cap 36)
  - delete the rest
- Settings expose: enable/disable, retention multiplier (0.5×–4×), and a "Back up now" button.

Restore (phase 2 UI): open a backup read-only in a second window with the same password; user can copy items across, or "Replace current vault with this backup" (which first snapshots the current one).

## 5. Merge semantics (`vault_core::merge`)

Inputs: `ours: &mut UnlockedVault`, `theirs: &UnlockedVault`, same `vault_id` (else error).

Per item id in `ours ∪ theirs`:

| ours | theirs | result |
|---|---|---|
| absent | present | take theirs (including tombstones) |
| present | absent | keep ours |
| both, one is tombstone | — | tombstone wins **if** `deleted_at ≥ other.modified_at`; otherwise the live item wins (edit after delete resurrects) |
| both live | — | field-level merge below; metadata (title, kind, favorite, tags) taken from whichever item has the greater `modified_at`; tie → greater `device_id` bytes |

Field-level merge, keyed by `field.id` (2026-10-31; never by name):

| ours | theirs | result |
|---|---|---|
| absent | present | take theirs, unless our `removed_fields` carries a marker for that id with `removed_at ≥ modified_at` |
| present | absent | keep ours, unless their `removed_fields` carries a marker for that id with `removed_at ≥ modified_at` |
| both | — | greater `modified_at` wins whole (name, kind, value, section travel together, so a rename is an edit); tie → greater `device_id` of the owning item; tie → greater canonical CBOR bytes of the field (symmetric, so both devices converge in one round; bug hunt 2026-10-31) |

`removed_fields` markers are unioned (greatest `removed_at` per id); a field edited strictly after its marker survives and the marker is dropped on both sides. Markers are never dropped by a local removal; a merge caps them at 64 by dropping, oldest first, only markers whose field neither side still holds. Accepted limit: a third device that was offline since before such a dropped marker can still bring that field back. The former "field deletion is not tracked" limit is closed. Metadata and both-tombstone ties (equal stamp and device id) are also broken by the greater canonical CBOR bytes of the item payload, so no "tie → ours" remains.

`history` is merged by union on `(value, replaced_at)`, sorted, capped to 10 newest; `removed_history` stamps are unioned (cap 10 newest) and any history entry whose `replaced_at` is in the set is dropped, so a user's deletion of a history entry survives merge. A later `set_field` producing an entry with a stamp already in the set gets `max(now, stamp+1)`, which the monotone stamp rule guarantees anyway. Markers are keyed by stamp alone: if two devices change the same password in the same millisecond from the same base and one side deletes that history stamp before merging, the conflict-loser value is dropped with it. Accepted.

`attachments` are merged by union on `id` (sorted by `added_at`, then `id`); `removed_attachments` tombstones are unioned with the greatest `removed_at` per id, and a ref is dropped when a tombstone for its id has `removed_at ≥ added_at`. Unlike fields, an attachment removal therefore survives a merge with a device that still holds the ref.

Result item `modified_at = max(ours, theirs)`. Merged item takes `device_id` of whichever side supplied the winning metadata.

**Header merge** (added 2026-10-30 after the bug hunt, V-01/V-03): the header carries `slots_modified_at`; `merge_from` takes the whole slot set, KDF parameters and `format_version` from the header that is greater by the tuple (`format_version`, `slots_modified_at`, `slots_device_id`); equal keeps ours (2026-10-31: the version ranks first because every slot AAD binds it, so a version 2 header always beats a version 1 header and an upgrade is never undone; the device id tie-break means both devices converge). When the other side wins, the in-memory vault key is replaced by theirs as well (their slots wrap their key); a later local slot change with a greater stamp wins back by LWW. A password change, slot add/remove, re-calibration or key rotation on one device therefore survives the other device's next save. The vault key is unchanged by a password change, so the other device keeps working with its cached key; a key rotation is detected as before (`KeyRotatedOnDisk`).

Timestamps are monotone per item: every write stamps `max(now, previous + 1)`, so a clock that went backwards cannot resurrect a deleted item or let an older edit win. If a merge changes an item's content without changing its `modified_at` (possible when both sides carry the same timestamp), the merge bumps `modified_at` by one so the manifest check and the other device see the change. Two devices converge within two merge rounds, or three when the `removed_fields` cap fires, since each side can apply the cap only after it has seen the peer drop the fields (2026-10-31).

`merge_from` returns `MergeReport` and a bool-equivalent "anything changed" so `vault-sync` can skip the write when nothing moved.

Clock skew: timestamps come from each device's wall clock. If skew exceeds a few seconds, the "wrong" edit may win on a true conflict. Accepted for v1; UI shows the losing value in field history for `password` fields, so nothing is lost. Do not add vector clocks.

## 6. Conflicted copies

Cloud providers resolve simultaneous writes by creating a sibling file instead of merging. Patterns to detect (case-insensitive, in `<dir>` only):

- Whole-package (iCloud): `<name> 2.vault/`, `<name> 3.vault/`, … and `<name> (<host>'s conflicted copy <date>).vault/`
- Per-file (Dropbox, Google Drive, Syncthing sync the files inside the package individually): `<name>.vault/vault (<host>'s conflicted copy <date>).bin`, `<name>.vault/vault 2.bin`, …
- Generic: any such candidate whose header `vault_id` equals ours

On watcher event for a file matching the Dropbox pattern or any new `*.vault` in `<dir>`:

```
1. parse; if vault_id != ours → ignore (it's some other vault the user put there)
2. unlock with cached key (if locked, defer to next unlock; keep a list of pending conflict paths)
3. ours.merge_from(theirs); save()
4. whole-package: copy any attachment blobs we lack (never replacing), then move the whole package to <name>.vault/backups/conflict-<timestamp>-<original name>/ — deferred to the next event while blobs referenced by the merged items are still missing from both sides; per-file: move the file to <name>.vault/backups/conflict-<timestamp>-<original name>.vault.bin
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
    pub fn poll(&mut self);                                                                 // drains watcher events on the caller's thread
    pub fn save(&mut self) -> Result<(), SyncError>;
    pub fn is_dirty(&self) -> bool;
    pub fn subscribe(&self) -> crossbeam_channel::Receiver<SyncEvent>;
    pub fn backups(&self) -> Result<Vec<BackupInfo>, SyncError>;
    pub fn backup_now(&mut self) -> Result<PathBuf, SyncError>;
    pub fn restore_from(&mut self, backup: &Path, password: &SecretString) -> Result<(), SyncError>;
    pub fn delete_backup(&mut self, backup: &Path) -> Result<(), SyncError>;   // user-initiated; path must be inside backups/ (file or conflict package); refuses the primary; any kind incl. Unsaved/Conflict

    // attachments (v1.1) — streaming; the ref is added to / removed from the item by the caller via `edit`
    pub fn add_attachment(&mut self, item: Uuid, name: &str, data: impl Read, size: u64, now: Millis) -> Result<Uuid, SyncError>; // seals + writes blob, appends ref, marks dirty
    pub fn open_attachment(&self, item: Uuid, id: Uuid) -> Result<AttachmentReader, SyncError>;  // streaming decrypt; NotDownloaded / Missing
    pub fn attachment_state(&self, id: Uuid) -> AttachmentState;                                  // Present | NotDownloaded | Missing
    pub fn remove_attachment(&mut self, item: Uuid, id: Uuid, now: Millis) -> Result<(), SyncError>; // drops the ref; blob goes via orphan cleanup
}

pub enum SyncEvent {
    Merged(MergeReport),
    ChangedWhileLocked,
    ConflictAbsorbed(PathBuf),
    CorruptOnDisk,
    ForeignVault,
    CloudUnavailable,
    BackupTaken(PathBuf),
    BackupDeleted(PathBuf),      // user-initiated delete_backup
    KeyMismatch,                 // on-disk file no longer opens with our cached key (password changed elsewhere); edits are kept, next unlock re-verifies
    KeyRotatedOnDisk,            // vault_key rotated elsewhere; must re-unlock with the password
    SaveBlocked(SaveBlocked),     // NewerVersion | ForeignVault; in-memory state kept; emitted once at first detection and once per refused save
    Error(String),
}

pub enum BackupKind { Snapshot, Unsaved, Conflict }
```

Backups carry a kind: `Snapshot` (policy in §4), `Unsaved` (taken on lock or quit while edits could not be saved), `Conflict` (absorbed conflict copy, §6). Retention prunes `Snapshot` only; `Unsaved` and `Conflict` are never pruned. `restore_from` snapshots the current file first and works even when the primary no longer parses.

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
