//! Error type for every fallible `SyncedVault` operation.

use std::path::PathBuf;

use vault_core::{AttachmentError, Uuid, VaultError};

use crate::cloud::CloudError;

/// Everything `vault-sync` can fail with.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// A filesystem operation on `path` failed.
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The vault bytes could not be parsed or unlocked.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The operation needs an unlocked vault.
    #[error("vault is locked")]
    Locked,
    /// `open` found no vault package at this path, or the package has no `vault.bin`.
    #[error("no vault at {}", .0.display())]
    NoVault(PathBuf),
    /// `open` was given a regular file. Vaults are package directories (`<name>.vault/`
    /// containing `vault.bin`); the earlier single-file layout is not supported or migrated.
    #[error(
        "{} is a file, not a vault package (a `.vault` folder containing vault.bin); \
         this vault format is no longer supported, create a new vault",
        .0.display()
    )]
    NotAPackage(PathBuf),
    /// `create` refuses to overwrite an existing path.
    #[error("{} already exists", .0.display())]
    AlreadyExists(PathBuf),
    /// `restore_from` was given a backup of a different vault.
    #[error("backup belongs to vault {found}, not {expected}")]
    ForeignVault { expected: Uuid, found: Uuid },
    /// The on-disk vault no longer opens with the in-memory vault key (another device rotated
    /// the key, or the file was rolled back). Saving is refused until the user re-enters the
    /// password through `unlock`, which re-opens the on-disk vault and merges the in-memory
    /// items into it.
    #[error("on-disk vault no longer opens with the cached key; re-enter the password")]
    KeyMismatch,
    /// Saving would overwrite a primary that must not be overwritten. Cleared when a valid
    /// file of this vault in a supported format is next seen on disk.
    #[error("{0}")]
    SaveBlocked(SaveBlocked),
    /// `delete_backup` was given a path that is not one of this vault's backups (an entry of
    /// `backups()`, resolved through symlinks, directly inside `<name>.vault/backups/`). The
    /// primary, the package itself and anything outside `backups/` are always refused.
    #[error("{} is not a backup of this vault", .0.display())]
    NotABackup(PathBuf),
    /// Another process (or another `SyncedVault` on the same package) held the package's
    /// advisory lock (`<name>.vault/.lock`, 03 §2) for longer than 10 s. Nothing was written;
    /// retry.
    #[error("another process is writing this vault")]
    SaveLockTimeout(PathBuf),
    /// The filesystem watcher could not be started.
    #[error("file watcher: {0}")]
    Watch(String),
    /// The cloud provider could not supply the file.
    #[error(transparent)]
    Cloud(#[from] CloudError),
    /// Sealing an attachment failed: larger than `MAX_ATTACHMENT_SIZE` (refused before any
    /// byte is read), the input was not exactly `size` bytes, or the input reader failed. No
    /// blob and no reference were left behind.
    #[error(transparent)]
    Attachment(#[from] AttachmentError),
    /// The item does not exist or holds no reference to this attachment (it was removed, or
    /// the id is wrong). Distinct from [`SyncError::AttachmentMissing`], where the reference
    /// exists but its blob does not.
    #[error("attachment {id} not found on this item")]
    AttachmentNotFound { item: Uuid, id: Uuid },
    /// The attachment blob is evicted to the cloud and did not download within
    /// `DOWNLOAD_TIMEOUT` (03 §1.1 `NotDownloaded`). Retry later.
    #[error("attachment {0} is not downloaded yet")]
    AttachmentNotDownloaded(Uuid),
    /// The item references the attachment but its blob is not in the attachments directory
    /// (not synced yet, deleted, or the vault was restored from a backup; 03 §1.1 `Missing`).
    #[error("attachment {0} is missing from the attachments directory")]
    AttachmentMissing(Uuid),
    /// The blob failed authentication (corrupt, truncated, swapped or not sealed for this
    /// reference). Raised by `AttachmentReader` as the payload of an `io::Error`; every byte
    /// already read from that reader must be discarded.
    #[error("attachment {0} is corrupt or tampered")]
    AttachmentTampered(Uuid),
}

impl SyncError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Why [`SyncError::SaveBlocked`] refuses to write the primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SaveBlocked {
    /// The primary was written by a newer format version; writing would downgrade it.
    #[error("the vault file was written by a newer version (format {0}); update this app")]
    NewerVersion(u16),
    /// The primary now holds a different vault (another `vault_id`).
    #[error("the vault file now holds a different vault; not overwriting it")]
    ForeignVault,
}
