//! Error type for every fallible `SyncedVault` operation.

use std::path::PathBuf;

use vault_core::{Uuid, VaultError};

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
    /// `open` found no file at this path.
    #[error("no vault file at {}", .0.display())]
    NoVault(PathBuf),
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
    /// The filesystem watcher could not be started.
    #[error("file watcher: {0}")]
    Watch(String),
    /// The cloud provider could not supply the file.
    #[error(transparent)]
    Cloud(#[from] CloudError),
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
