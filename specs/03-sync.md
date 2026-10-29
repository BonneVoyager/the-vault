# 03 — `vault-sync`: file sync, merge, backups

Model: the vault lives at a user-chosen path. iCloud Drive, Dropbox, Google Drive, a NAS mount, and `~/Documents` are all the same thing — a directory that something else may rewrite underneath us. One code path.

Dependencies: `vault-core`, `notify` (+ `notify-debouncer-full`), `tempfile`, `fs2` or `rustix` (for `fsync`), `thiserror`, `tracing`. No async runtime; a dedicated thread for the watcher.

## 1. Directory layout

```
<dir>/
  <name>.vault                      the vault
  <name>.vault.attachments/         (v1.1)
  <name>.vault.backups/
    <name>-2026-10-28T14-03-11Z.vault
    ...
  .<name>.vault.tmp-<8 hex>         transient; never left behind on clean exit
```

Everything in `.backups/` is a complete, independently-openable vault file. Backups are encrypted; the directory is safe to sync.

## 2. Writing — `SyncedVault::save`

```
1. bytes = vault.serialize()
2. write bytes to <dir>/.<name>.vault.tmp-<rand>   (O_CREAT|O_EXCL, mode 0600)
3. fsync(tmp)
4. rename(tmp, <dir>/<name>.vault)                 atomic on APFS / HFS+ / ext4
5. fsync(dir)                                      best-effort; ignore ENOTSUP
6. record (mtime, size, blake3(bytes)) as `last_written`
7. maybe_backup(bytes)                             §4
```

Never write in place. Never truncate-then-write. If step 4 fails, delete the tmp and surface the error; the old file is intact.

## 3. Watching and reacting to external changes

Watcher: `notify` recursive on `<dir>` (non-recursive is enough, but iCloud sometimes fires on the parent), debounced 500 ms. Events on paths other than `<name>.vault` and conflict-copy patterns (§6) are ignored.

On a debounced event for `<name>.vault`:

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
- Snapshot = copy of the exact bytes just written, named `<name>-<UTC ISO8601 with - instead of :>.vault`.
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

Field-level merge, keyed by `field.name`:

| ours | theirs | result |
|---|---|---|
| absent | present | take theirs |
| present | absent | keep ours (field deletion is not tracked in v1; a removed field reappears if the other side still has it — accepted) |
| both | — | greater `modified_at` wins; tie → greater `device_id` of the owning item; tie → ours |

`history` is merged by union on `(value, replaced_at)`, sorted, capped to 10 newest.

Result item `modified_at = max(ours, theirs)`. Merged item takes `device_id` of whichever side supplied the winning metadata.

Timestamps are monotone per item: every write stamps `max(now, previous + 1)`, so a clock that went backwards cannot resurrect a deleted item or let an older edit win. If a merge changes an item's content without changing its `modified_at` (possible when both sides carry the same timestamp), the merge bumps `modified_at` by one so the manifest check and the other device see the change. Two devices converge within two merge rounds.

`merge_from` returns `MergeReport` and a bool-equivalent "anything changed" so `vault-sync` can skip the write when nothing moved.

Clock skew: timestamps come from each device's wall clock. If skew exceeds a few seconds, the "wrong" edit may win on a true conflict. Accepted for v1; UI shows the losing value in field history for `password` fields, so nothing is lost. Do not add vector clocks.

## 6. Conflicted copies

Cloud providers resolve simultaneous writes by creating a sibling file instead of merging. Patterns to detect (case-insensitive, in `<dir>` only):

- Dropbox: `<name> (<host>'s conflicted copy <date>).vault`
- iCloud: `<name> 2.vault`, `<name> 3.vault`, … (iCloud renames the loser with a numeric suffix)
- Generic: any `*.vault` in `<dir>` whose header `vault_id` equals ours and whose path is not the primary

On watcher event for a file matching the Dropbox pattern or any new `*.vault` in `<dir>`:

```
1. parse; if vault_id != ours → ignore (it's some other vault the user put there)
2. unlock with cached key (if locked, defer to next unlock; keep a list of pending conflict paths)
3. ours.merge_from(theirs); save()
4. move the conflict file to <name>.vault.backups/conflict-<timestamp>-<original filename>
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
    pub fn lock(&mut self);                                                                 // zeroizes key, drops items; unsaved edits are snapshotted to a backup first
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
}

pub enum SyncEvent {
    Merged(MergeReport),
    ChangedWhileLocked,
    ConflictAbsorbed(PathBuf),
    CorruptOnDisk,
    ForeignVault,
    CloudUnavailable,
    BackupTaken(PathBuf),
    KeyMismatch,                 // on-disk file no longer opens with our cached key (password changed elsewhere); edits are kept, next unlock re-verifies
    KeyRotatedOnDisk,            // vault_key rotated elsewhere; must re-unlock with the password
    SaveBlocked(SaveBlockReason), // NewerVersion | ForeignVault; in-memory state kept
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
