//! Events delivered through [`crate::SyncedVault::subscribe`] (03 §8).

use std::path::PathBuf;

use vault_core::MergeReport;

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
    /// The on-disk vault no longer opens with the cached vault key (another device rotated
    /// the key, or the file was rolled back to an empty vault). In-memory state is kept and the
    /// disk is not touched; `save` refuses with `SyncError::KeyMismatch`. Prompt for the
    /// password and call `unlock`, which re-opens the on-disk vault and merges the in-memory
    /// items into it.
    KeyMismatch,
    /// After [`SyncEvent::KeyMismatch`], the password opened the on-disk vault and its header,
    /// slots and vault key were adopted, with the in-memory items merged in (a
    /// [`SyncEvent::Merged`] follows). Usually another device rotated the key or changed the
    /// password. It can also be a rollback to an older file: a pre-rotation file still opens
    /// with the same password, so a rollback is indistinguishable from a rotation by design.
    /// Worth telling the user.
    KeyRotatedOnDisk,
    /// Orphan cleanup after a save (03 §1.1) deleted this many attachment blobs that no item
    /// references any more and that were older than the 24 h grace period. Stale tmp files
    /// are not counted.
    AttachmentsPruned(usize),
}
