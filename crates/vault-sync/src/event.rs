//! Events delivered through [`crate::SyncedVault::subscribe`] (03 §8).

use std::path::PathBuf;

use vault_core::MergeReport;

use crate::error::SaveBlocked;

/// Something the app may want to react to, delivered through `subscribe`. Watcher-driven
/// events are emitted from `SyncedVault::poll` (and from `unlock` for work deferred while
/// locked), always on the caller's thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    Merged(MergeReport),
    ChangedWhileLocked,
    ConflictAbsorbed(PathBuf),
    CorruptOnDisk,
    ForeignVault,
    CloudUnavailable,
    BackupTaken(PathBuf),
    Error(String),
    /// The on-disk vault no longer opens with the cached vault key and does not look like a key
    /// rotation (03 §8 "password changed elsewhere"): our password slots were replaced or
    /// removed, or the KDF parameters changed. Also reported when the slots are unchanged but
    /// the items do not open (tampering or a foreign rewrite; the password unlock tells which).
    /// In-memory state is kept and the disk is not touched; `save` refuses with
    /// `SyncError::KeyMismatch`. Prompt for the password and call `unlock`, which re-opens the
    /// on-disk vault and merges the in-memory items into it ([`SyncEvent::Merged`] follows).
    KeyMismatch,
    /// The on-disk vault no longer opens with the cached vault key, and its header looks like
    /// another device rotated the vault key (03 §8): every password slot we hold is still
    /// there under the same id with the same KDF parameters, but rewrapped (new nonce or
    /// wrapped key). Handled exactly like [`SyncEvent::KeyMismatch`]: in-memory state is kept,
    /// `save` refuses with `SyncError::KeyMismatch`, and the user must re-enter the password
    /// through `unlock`, which adopts the rotated vault and merges the in-memory items into it
    /// ([`SyncEvent::Merged`] follows). A rollback of the file to a pre-rotation version looks
    /// the same, by design (no rollback protection in the format).
    KeyRotatedOnDisk,
    /// A save was refused (03 §3): the primary was written by a newer format version or now
    /// holds a different vault. The file is untouched and the in-memory state is kept.
    /// Emitted when the watcher (or the pre-write read of a `save`) first sees such a file,
    /// and on every refused `save` after that.
    SaveBlocked(SaveBlocked),
    /// `delete_backup` removed this backup (a snapshot file or a conflict package directory).
    BackupDeleted(PathBuf),
    /// Orphan cleanup (03 §1.1) moved this many attachment blobs that no item references any
    /// more and that were older than the 24 h grace period into quarantine
    /// (`attachments/orphaned/`, deleted there after 30 days; security review 2026-11-26,
    /// M-02). Stale tmp files and quarantine expiry are not counted.
    AttachmentsPruned(usize),
    /// `vault.bin` disappeared while the vault was unlocked (deleted, or not yet re-created
    /// by a provider). The in-memory vault is kept and marked dirty: the next `save`
    /// recreates the file (without replacing one that reappeared meanwhile), and `lock`
    /// writes an Unsaved backup if that has not happened. Emitted once until the primary is
    /// seen or written again.
    PrimaryMissing,
    /// A whole-package conflicted copy (03 §6) at this path was merged and saved, but moving
    /// it into `backups/` is deferred: blobs that its items reference (and the merged vault
    /// still references) are missing both from our `attachments/` and from the copy's, so the
    /// provider is presumably still delivering them. The package stays where it is; when the
    /// blobs arrive they are copied and the package is moved
    /// ([`SyncEvent::ConflictAbsorbed`] follows). Emitted once per package while it waits,
    /// not on every re-check; it comes again after the package was absorbed or disappeared,
    /// and once more for a package still waiting after `lock` + unlock or after watching is
    /// stopped and restarted. The path is as received from the filesystem (not sanitised).
    WaitingForBlobs(PathBuf),
    /// A conflict candidate at this path (03 §6: a whole-package sibling, whose `vault.bin` is
    /// meant, or a per-file copy such as `vault 2.bin`) is not a vault file this build can open: it
    /// is a symlink, FIFO or other special file (03 §2 D-1; never followed, opened or moved), it
    /// does not parse (random bytes, truncated) or carries a format version other than ours (newer,
    /// or 0). It is not ours to judge, so it is left where it is (never deleted or moved) and not
    /// merged. Emitted once per candidate version while it stays unreadable, not on every re-check:
    /// it comes again when the file read (the copy, or a package's `vault.bin`) changes contents
    /// (the same bytes re-delivered under a new mtime stay silent), after the candidate was
    /// absorbed, disappeared or became readable, and once more for a candidate still unreadable
    /// after `lock` + unlock or after watching is stopped and restarted. It can fire while locked:
    /// the file is parsed before the locked check (03 §6 step 1 before step 2); a candidate first
    /// reported while locked is reported once more by the next unlock. A copy whose download fails
    /// is [`SyncEvent::CloudUnavailable`] instead, one that parses but holds another vault is
    /// [`SyncEvent::ForeignVault`], and one that cannot be read at all (I/O error, over
    /// [`crate::MAX_VAULT_FILE_SIZE`]) is [`SyncEvent::Error`]. The path is as received from the
    /// filesystem (not sanitised).
    UnreadableConflict(PathBuf),
}
