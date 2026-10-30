//! Atomic replace of the package's `vault.bin` (03 §2 steps 2-5) and of attachment blobs (03 §1.1).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use rand::rngs::OsRng;

use crate::error::SyncError;

/// Directory containing `path`; `.` for a bare file name.
pub(crate) fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// `<dir>/.<file name>.tmp-<8 hex>`, e.g. `<name>.vault/.vault.bin.tmp-<8 hex>` (03 §1).
fn tmp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned());
    let suffix = OsRng.next_u32();
    parent_dir(path).join(format!(".{name}.tmp-{suffix:08x}"))
}

/// How the finished tmp file becomes the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `rename(tmp, target)`: atomically replaces an existing target (`save`).
    Replace,
    /// `link(tmp, target)` then unlink tmp: fails with [`SyncError::AlreadyExists`] if the
    /// target appeared since the caller checked (`create`), never clobbering it.
    NoReplace,
}

/// Removes the tmp file on drop unless defused, so neither an error path nor a panic can leave
/// one behind.
struct TmpGuard<'a> {
    path: &'a Path,
    armed: bool,
}

impl TmpGuard<'_> {
    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl Drop for TmpGuard<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Err(e) = fs::remove_file(self.path)
        {
            tracing::warn!(tmp = %self.path.display(), error = %e, "could not remove tmp file");
        }
    }
}

/// Write `bytes` to a fresh tmp file (O_CREAT|O_EXCL, 0600), fsync it, move it to `path` per
/// `mode`, then best-effort fsync the directory. On any failure the tmp is removed and `path`
/// is untouched.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: Mode) -> Result<(), SyncError> {
    write_atomic_with(path, bytes, mode, |src, dst| fs::hard_link(src, dst))
}

/// [`write_atomic`] with the content streamed by `fill` instead of passed as a slice. `fill`
/// gets the open tmp file and its path (for error reporting); if it fails, the tmp is removed
/// and its error returned with `path` untouched.
pub(crate) fn write_atomic_stream(
    path: &Path,
    mode: Mode,
    fill: impl FnOnce(&mut File, &Path) -> Result<(), SyncError>,
) -> Result<(), SyncError> {
    write_atomic_inner(path, mode, fill, |src, dst| fs::hard_link(src, dst))
}

/// [`write_atomic`] with the hard-link call injectable, so tests can simulate filesystems
/// without hard links.
fn write_atomic_with(
    path: &Path,
    bytes: &[u8],
    mode: Mode,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), SyncError> {
    write_atomic_inner(
        path,
        mode,
        |file, tmp| file.write_all(bytes).map_err(|e| SyncError::io(tmp, e)),
        link,
    )
}

fn write_atomic_inner(
    path: &Path,
    mode: Mode,
    fill: impl FnOnce(&mut File, &Path) -> Result<(), SyncError>,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), SyncError> {
    let tmp = tmp_path(path);
    let mut file = open_tmp(&tmp).map_err(|e| SyncError::io(&tmp, e))?;
    let mut guard = TmpGuard {
        path: &tmp,
        armed: true,
    };

    fill(&mut file, &tmp)?;
    file.sync_all().map_err(|e| SyncError::io(&tmp, e))?;
    drop(file);

    match mode {
        Mode::Replace => {
            fs::rename(&tmp, path).map_err(|e| SyncError::io(path, e))?;
            guard.defuse();
        }
        Mode::NoReplace => match link(&tmp, path) {
            // The guard now unlinks the tmp name; the data lives on under `path`.
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(SyncError::AlreadyExists(path.to_owned()));
            }
            Err(e) => {
                // exFAT, some SMB mounts: no hard links. Fall back to check-then-rename, which
                // reopens a narrow race window but is the best these filesystems allow.
                tracing::warn!(path = %path.display(), error = %e, "hard link unsupported; falling back to rename");
                match fs::symlink_metadata(path) {
                    Ok(_) => return Err(SyncError::AlreadyExists(path.to_owned())),
                    Err(e) if e.kind() == ErrorKind::NotFound => {}
                    Err(e) => return Err(SyncError::io(path, e)),
                }
                fs::rename(&tmp, path).map_err(|e| SyncError::io(path, e))?;
                guard.defuse();
            }
        },
    }
    drop(guard);

    // Step 5: best-effort; some filesystems refuse to fsync a directory (ENOTSUP, EINVAL).
    let dir = parent_dir(path);
    if let Err(e) = File::open(dir).and_then(|d| d.sync_all()) {
        tracing::debug!(dir = %dir.display(), error = %e, "directory fsync skipped");
    }
    Ok(())
}

fn open_tmp(tmp: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn tmp_name_matches_layout() {
        let tmp = tmp_path(Path::new("/x/My.vault/vault.bin"));
        let name = tmp.file_name().unwrap().to_str().unwrap();
        assert_eq!(tmp.parent().unwrap(), Path::new("/x/My.vault"));
        let hex = name.strip_prefix(".vault.bin.tmp-").unwrap();
        assert_eq!(hex.len(), 8);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rename_failure_removes_tmp_and_keeps_target() {
        // Renaming a file over a non-empty directory fails, after the tmp was written.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"old").unwrap();

        let err = write_atomic(&target, b"new", Mode::Replace).unwrap_err();
        assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
        assert!(leftovers(dir.path()).is_empty());
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"old");
    }

    #[test]
    fn replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        fs::write(&target, b"old").unwrap();
        write_atomic(&target, b"new", Mode::Replace).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn no_replace_refuses_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        fs::write(&target, b"theirs").unwrap();

        let err = write_atomic(&target, b"ours", Mode::NoReplace).unwrap_err();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
        assert_eq!(fs::read(&target).unwrap(), b"theirs");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn no_replace_creates_new_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        write_atomic(&target, b"ours", Mode::NoReplace).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ours");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn stream_fill_failure_removes_tmp_and_keeps_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.bin");
        let err = write_atomic_stream(&target, Mode::Replace, |file, tmp| {
            file.write_all(b"partial").unwrap();
            Err(SyncError::io(tmp, ErrorKind::InvalidData.into()))
        })
        .unwrap_err();
        assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
        assert!(!target.exists());
        assert!(leftovers(dir.path()).is_empty());

        write_atomic_stream(&target, Mode::Replace, |file, tmp| {
            file.write_all(b"whole").map_err(|e| SyncError::io(tmp, e))
        })
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"whole");
        assert!(leftovers(dir.path()).is_empty());
    }

    fn unsupported(_: &Path, _: &Path) -> std::io::Result<()> {
        Err(std::io::Error::from(ErrorKind::Unsupported))
    }

    #[test]
    fn no_replace_falls_back_to_rename_without_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        write_atomic_with(&target, b"ours", Mode::NoReplace, unsupported).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ours");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn no_replace_fallback_refuses_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        fs::write(&target, b"theirs").unwrap();
        let err = write_atomic_with(&target, b"ours", Mode::NoReplace, unsupported).unwrap_err();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
        assert_eq!(fs::read(&target).unwrap(), b"theirs");
        assert!(leftovers(dir.path()).is_empty());
    }
}
