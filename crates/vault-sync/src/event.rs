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
    /// Orphan cleanup after a save (03 §1.1) deleted this many attachment blobs that no item
    /// references any more and that were older than the 24 h grace period. Stale tmp files
    /// are not counted.
    AttachmentsPruned(usize),
    /// `vault.bin` disappeared while the vault was unlocked (deleted, or not yet re-created
    /// by a provider). The in-memory vault is kept and marked dirty: the next `save`
    /// recreates the file (without replacing one that reappeared meanwhile), and `lock`
    /// writes an Unsaved backup if that has not happened. Emitted once until the primary is
    /// seen or written again.
    PrimaryMissing,
}
