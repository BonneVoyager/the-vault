#![forbid(unsafe_code)]
//! `vault-sync`: atomic writes, file watching, backup rotation and conflict handling
//! (`specs/03-sync.md`).
//!
//! [`SyncedVault`] opens, unlocks, edits and atomically saves a `.vault` file (§1, §2, §7, §8),
//! takes snapshots with retention (§4), and reconciles external changes and conflicted copies
//! (§3, §6). Attachment blobs (§1.1, v1.1) live next to the vault in `<name>.vault.attachments/`:
//! [`SyncedVault::add_attachment`] writes them atomically, [`AttachmentReader`] streams them
//! decrypted, and every save that writes the file prunes unreferenced blobs after 24 h.
//!
//! # Threading
//!
//! [`SyncedVault::start_watching`] starts `notify`'s watcher and debounce threads. Those
//! threads only classify paths and queue signals; they never touch the vault, read file
//! contents or hold key material. The app calls [`SyncedVault::poll`] from its own tick (the
//! thread that also calls `save` and `lock`), which drains the queue and runs the §3 and §6
//! steps there: stat, echo check, parse, merge, save, move conflict copies, emit
//! [`SyncEvent`]s. So `SyncedVault` is `Send` but needs no internal locking.

mod atomic;
mod attachments;
mod backup;
mod cloud;
mod error;
mod event;
mod synced;
mod watch;

pub use attachments::{AttachmentReader, AttachmentState, ORPHAN_GRACE, STALE_TMP_GRACE};
pub use backup::{
    BackupInfo, BackupKind, RETENTION_MULTIPLIER_DEFAULT, RETENTION_MULTIPLIER_MAX,
    RETENTION_MULTIPLIER_MIN, retain,
};
pub use cloud::{CloudError, CloudHooks, NoopHooks};
pub use error::{SaveBlocked, SyncError};
pub use event::SyncEvent;
pub use synced::{DOWNLOAD_TIMEOUT, LastWritten, LockedSummary, SyncedVault};
pub use watch::DEBOUNCE;
