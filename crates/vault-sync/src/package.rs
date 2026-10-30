//! The vault package layout (03 §1): a `<name>.vault/` directory holding the vault file, the
//! attachment blobs and the backups.
//!
//! ```text
//! <name>.vault/
//!   vault.bin                       the vault file (01)
//!   attachments/<id hex>.bin        immutable blobs (03 §1.1)
//!   backups/<name>-<stamp>.vault.bin snapshots, unsaved copies, absorbed conflict packages
//!   .vault.bin.tmp-<8 hex>          transient
//!   .lock                           advisory save lock (03 §2), empty
//! ```

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::error::SyncError;

/// File name of the vault file inside a package.
pub const VAULT_FILE_NAME: &str = "vault.bin";
/// Attachment blobs directory inside a package.
pub(crate) const ATTACHMENTS_DIR: &str = "attachments";
/// Backups directory inside a package.
pub(crate) const BACKUPS_DIR: &str = "backups";
/// Extension of a package directory.
pub(crate) const PACKAGE_EXT: &str = ".vault";

/// `<package>/vault.bin`.
pub(crate) fn vault_file(package: &Path) -> PathBuf {
    package.join(VAULT_FILE_NAME)
}

/// Advisory lock file inside a package (03 §2).
pub(crate) const LOCK_FILE_NAME: &str = ".lock";

/// `<package>/.lock`.
pub(crate) fn lock_file(package: &Path) -> PathBuf {
    package.join(LOCK_FILE_NAME)
}

/// `<package>/attachments`.
pub(crate) fn attachments_dir(package: &Path) -> PathBuf {
    package.join(ATTACHMENTS_DIR)
}

/// `<package>/backups`.
pub(crate) fn backups_dir(package: &Path) -> PathBuf {
    package.join(BACKUPS_DIR)
}

/// The last path component (`test.vault`); `vault` if there is none.
pub(crate) fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned())
}

/// `<name>` in `<name>.vault`; the whole directory name if it lacks the extension.
pub(crate) fn vault_name(package: &Path) -> String {
    let f = file_name(package);
    match f.strip_suffix(PACKAGE_EXT) {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => f,
    }
}

fn dir_builder() -> fs::DirBuilder {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

/// Create `dir` (0700); [`SyncError::AlreadyExists`] if anything is already at that path.
pub(crate) fn create_new_dir(dir: &Path) -> Result<(), SyncError> {
    match dir_builder().create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            Err(SyncError::AlreadyExists(dir.to_owned()))
        }
        Err(e) => Err(SyncError::io(dir, e)),
    }
}

/// Create `dir` (0700) if needed.
pub(crate) fn ensure_dir(dir: &Path) -> Result<(), SyncError> {
    match dir_builder().create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        Err(e) => Err(SyncError::io(dir, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let p = Path::new("/x/My.vault");
        assert_eq!(vault_file(p), Path::new("/x/My.vault/vault.bin"));
        assert_eq!(attachments_dir(p), Path::new("/x/My.vault/attachments"));
        assert_eq!(backups_dir(p), Path::new("/x/My.vault/backups"));
        assert_eq!(vault_name(p), "My");
        assert_eq!(vault_name(Path::new("/x/plain")), "plain");
        assert_eq!(vault_name(Path::new("/x/.vault")), ".vault");
    }
}
