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

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use unicode_normalization::{UnicodeNormalization, is_nfc};

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

/// `s` in Unicode NFC. Cloud providers may deliver a name in another normalisation form (NFD)
/// than the one we wrote, so every comparison of names goes through this; nothing on disk is
/// ever renamed.
pub(crate) fn nfc(s: &str) -> Cow<'_, str> {
    if is_nfc(s) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.nfc().collect())
    }
}

/// Comparison key for a name that matches case-insensitively (like the default APFS volume)
/// and normalisation-insensitively: NFC, Unicode lowercase, NFC again (lowercasing can
/// decompose).
pub(crate) fn fold_name(s: &str) -> String {
    nfc(&nfc(s).to_lowercase()).into_owned()
}

/// Whether two path components are equal after NFC (case-sensitive). Non-UTF-8 components
/// compare byte-wise.
pub(crate) fn same_component(a: &OsStr, b: &OsStr) -> bool {
    a == b
        || match (a.to_str(), b.to_str()) {
            (Some(a), Some(b)) => nfc(a) == nfc(b),
            _ => false,
        }
}

/// [`Path::strip_prefix`] with components compared by [`same_component`]. The remainder
/// keeps `path`'s own spelling.
pub(crate) fn strip_prefix_nfc<'a>(path: &'a Path, prefix: &Path) -> Option<&'a Path> {
    let mut rest = path.components();
    for want in prefix.components() {
        let got = rest.next()?;
        if !same_component(got.as_os_str(), want.as_os_str()) {
            return None;
        }
    }
    Some(rest.as_path())
}

/// Identity of a path for bookkeeping (dedupe sets, per-path reports): the path in NFC, so
/// the spellings a watcher event and a directory listing deliver count as one. Only for
/// keys; file operations use the path as received.
pub(crate) fn path_key(path: &Path) -> PathBuf {
    match path.to_str() {
        Some(s) => PathBuf::from(nfc(s).into_owned()),
        None => path.to_owned(),
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

/// Whether `dir` (a package subdirectory: `attachments/`, `backups/`) exists as a real
/// directory. `Ok(false)` if nothing is there; [`SyncError::UnsafePackageDir`] if a symlink
/// (never followed: it could redirect writes, listing and deletion outside the package) or
/// anything other than a directory is there.
pub(crate) fn check_dir(dir: &Path) -> Result<bool, SyncError> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_dir() => Ok(true),
        Ok(_) => Err(SyncError::UnsafePackageDir(dir.to_owned())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(SyncError::io(dir, e)),
    }
}

/// Create `dir` (0700) if needed; refuses a symlink or non-directory there (see
/// [`check_dir`]).
pub(crate) fn ensure_dir(dir: &Path) -> Result<(), SyncError> {
    if check_dir(dir)? {
        return Ok(());
    }
    match dir_builder().create(dir) {
        Ok(()) => Ok(()),
        // Raced with another creator: accept only a real directory.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => check_dir(dir).and_then(|real| {
            if real {
                Ok(())
            } else {
                Err(SyncError::io(dir, e))
            }
        }),
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

    #[test]
    fn names_compare_after_nfc() {
        let composed = "\u{c4}rzte.vault"; // Ä as one code point
        let decomposed = "A\u{308}rzte.vault"; // A + combining diaeresis
        assert_ne!(composed, decomposed);
        assert_eq!(nfc(decomposed), composed);
        assert!(matches!(nfc(composed), Cow::Borrowed(_)));
        assert_eq!(fold_name(decomposed), fold_name("\u{e4}RZTE.VAULT"));
        assert_ne!(fold_name(decomposed), fold_name("Arzte.vault"));
        assert!(same_component(OsStr::new(composed), OsStr::new(decomposed)));
        assert!(!same_component(
            OsStr::new(composed),
            OsStr::new("\u{e4}rzte.vault")
        ));

        let path = PathBuf::from(format!("/d/{decomposed}/vault.bin"));
        let pkg = PathBuf::from(format!("/d/{composed}"));
        assert_eq!(strip_prefix_nfc(&path, &pkg), Some(Path::new("vault.bin")));
        assert_eq!(strip_prefix_nfc(&pkg, &pkg), Some(Path::new("")));
        assert_eq!(strip_prefix_nfc(&path, Path::new("/d/Arzte.vault")), None);
        assert_eq!(strip_prefix_nfc(Path::new("/d"), &pkg), None);
        assert_eq!(
            path_key(&path),
            PathBuf::from(format!("/d/{composed}/vault.bin"))
        );
    }

    #[test]
    fn ensure_dir_refuses_symlinks_and_files() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        ensure_dir(&real).unwrap();
        ensure_dir(&real).unwrap();
        assert!(check_dir(&real).unwrap());
        assert!(!check_dir(&dir.path().join("none")).unwrap());

        let outside = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(matches!(
            ensure_dir(&link),
            Err(SyncError::UnsafePackageDir(_))
        ));
        assert!(matches!(
            check_dir(&link),
            Err(SyncError::UnsafePackageDir(_))
        ));

        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(
            ensure_dir(&file),
            Err(SyncError::UnsafePackageDir(_))
        ));
    }
}
