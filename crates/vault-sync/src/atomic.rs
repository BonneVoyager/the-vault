//! Atomic replace of the package's `vault.bin` (03 §2 steps 2-5) and of attachment blobs (03 §1.1).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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

/// Identity of a file version: `(dev, ino, size, mtime)`, plus the blake3 of its bytes when
/// the reader knows them. Every atomic replace makes a new inode, and an in-place write
/// changes size or mtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileId {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: Option<SystemTime>,
    hash: Option<[u8; 32]>,
}

impl FileId {
    pub(crate) fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime: meta.modified().ok(),
            hash: None,
        }
    }

    /// The same identity, recording that the version's bytes hash to `hash` (blake3).
    pub(crate) fn with_hash(self, hash: [u8; 32]) -> Self {
        Self {
            hash: Some(hash),
            ..self
        }
    }

    /// Whether the file now at `path` is still this version (03 §2 step 4): the same
    /// `(dev, ino, size, mtime)`, or, when only `(dev, ino)` differ, the same size and blake3
    /// of its current bytes (SMB/FUSE mounts renumber inodes on lookup; iCloud rewrites the
    /// same bytes). The bytes are read through one no-follow handle, at most `size + 1` of
    /// them. Missing, symlinked or unreadable counts as changed.
    fn still_at(&self, path: &Path) -> bool {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        let current = FileId::of(&meta);
        if (current.dev, current.ino, current.size, current.mtime)
            == (self.dev, self.ino, self.size, self.mtime)
        {
            return true;
        }
        let (Some(hash), true) = (
            self.hash,
            (current.size, current.mtime) == (self.size, self.mtime),
        ) else {
            return false;
        };
        let Ok(file) = crate::package::open_regular(path) else {
            return false;
        };
        let mut bytes = Vec::with_capacity(usize::try_from(self.size).unwrap_or(0));
        if file
            .take(self.size.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
        {
            return false;
        }
        let same = bytes.len() as u64 == self.size && *blake3::hash(&bytes).as_bytes() == hash;
        if same {
            tracing::debug!(path = %path.display(), "target renumbered but unchanged; replacing it");
        }
        same
    }
}

/// How the finished tmp file becomes the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `rename(tmp, target)`: atomically replaces an existing target (blobs).
    Replace,
    /// [`Mode::Replace`], but only if the target is still exactly the file identified (its
    /// `lstat` right before the rename); otherwise
    /// [`SyncError::PrimaryChangedDuringSave`] and nothing is renamed (`save`, restore).
    ReplaceIf(FileId),
    /// `renameatx_np(tmp, target, RENAME_EXCL)` (or, where unsupported, `link` then unlink
    /// tmp): fails with [`SyncError::AlreadyExists`] if the target appeared since the caller
    /// checked (`create`, backups, blobs), never clobbering it.
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

/// The filesystem calls `write_atomic` makes after the tmp is written, injectable so tests can
/// simulate volumes without native no-replace rename or hard links, and directory fsync
/// failures.
#[derive(Clone, Copy)]
struct FsOps {
    /// `rename(from, to)` that fails with `EEXIST` instead of replacing `to`.
    rename_exclusive: fn(&Path, &Path) -> std::io::Result<()>,
    /// `link(from, to)`; fails with `EEXIST` if `to` exists.
    hard_link: fn(&Path, &Path) -> std::io::Result<()>,
    /// fsync of the directory at the given path.
    sync_dir: fn(&Path) -> std::io::Result<()>,
    /// Runs right before the pre-rename identity checks with `(tmp, target)`; a no-op except
    /// in tests, which swap files there.
    before_checks: fn(&Path, &Path),
}

const REAL_FS: FsOps = FsOps {
    rename_exclusive,
    hard_link: |src, dst| fs::hard_link(src, dst),
    sync_dir: |dir| File::open(dir).and_then(|d| d.sync_all()),
    before_checks: |_, _| {},
};

/// `renameatx_np(from, to, RENAME_EXCL)` on macOS (`renameat2(RENAME_NOREPLACE)` on Linux):
/// atomic, never replaces `to`.
fn rename_exclusive(from: &Path, to: &Path) -> std::io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(std::io::Error::from)
}

/// Whether `e` from a syscall means "this volume does not support that operation" (ENOTSUP,
/// EOPNOTSUPP, EINVAL, ENOSYS or `Unsupported`), as opposed to a real failure.
fn is_unsupported(e: &std::io::Error) -> bool {
    use rustix::io::Errno;
    e.kind() == ErrorKind::Unsupported
        || e.raw_os_error().is_some_and(|c| {
            [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::INVAL, Errno::NOSYS]
                .iter()
                .any(|n| n.raw_os_error() == c)
        })
}

/// 03 §2 step 5: a directory fsync error that is ignored (the filesystem cannot fsync a
/// directory: ENOTSUP / EOPNOTSUPP / EINVAL, or anything std classifies as `Unsupported`,
/// which includes ENOSYS). Anything else (EIO, ENOSPC, EACCES, ...) is surfaced.
pub(crate) fn dir_sync_ignorable(e: &std::io::Error) -> bool {
    use rustix::io::Errno;
    e.kind() == ErrorKind::Unsupported
        || e.raw_os_error().is_some_and(|c| {
            [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::INVAL]
                .iter()
                .any(|n| n.raw_os_error() == c)
        })
}

/// What [`write_atomic_stat`] returns once the target is in place.
pub(crate) struct Written {
    /// `fstat` of the tmp handle after its fsync, before the rename (`None` if it failed).
    pub(crate) tmp_stat: Option<fs::Metadata>,
    /// Outcome of the directory fsync (step 5). `Err` means the new file IS at `path` (the
    /// rename happened) but its directory entry may not be durable yet: callers must treat
    /// the write as not done (retry), never roll it back.
    pub(crate) dir_sync: Result<(), SyncError>,
}

/// Write `bytes` to a fresh tmp file (O_CREAT|O_EXCL, 0600), fsync it, move it to `path` per
/// `mode`, then fsync the directory. The tmp stays open until the move; right before it, the
/// tmp path must still be the inode written through that handle (`lstat` vs `fstat`: same
/// dev and ino) or the write fails with [`SyncError::UnsafePackageEntry`]. On any failure
/// before the move the tmp is removed and `path` is untouched. A directory fsync failure other than "unsupported" is returned as an
/// error although `path` already holds the new file.
#[cfg(test)]
fn write_atomic(path: &Path, bytes: &[u8], mode: Mode) -> Result<(), SyncError> {
    write_atomic_with(path, bytes, mode, REAL_FS)?.dir_sync
}

/// [`write_atomic`], reporting the directory fsync separately (see [`Written`]) together
/// with the tmp handle's `fstat` taken after its fsync and before the rename. Rename and link
/// keep the inode, mtime and size, so a later stat of `path` that disagrees shows the file
/// was replaced since.
pub(crate) fn write_atomic_stat(
    path: &Path,
    bytes: &[u8],
    mode: Mode,
) -> Result<Written, SyncError> {
    write_atomic_with(path, bytes, mode, REAL_FS)
}

/// [`write_atomic`] with the content streamed by `fill` instead of passed as a slice. `fill`
/// gets the open tmp file and its path (for error reporting); if it fails, the tmp is removed
/// and its error returned with `path` untouched.
pub(crate) fn write_atomic_stream(
    path: &Path,
    mode: Mode,
    fill: impl FnOnce(&mut File, &Path) -> Result<(), SyncError>,
) -> Result<(), SyncError> {
    write_atomic_inner(path, mode, fill, REAL_FS)?.dir_sync
}

fn write_atomic_with(
    path: &Path,
    bytes: &[u8],
    mode: Mode,
    ops: FsOps,
) -> Result<Written, SyncError> {
    write_atomic_inner(
        path,
        mode,
        |file, tmp| file.write_all(bytes).map_err(|e| SyncError::io(tmp, e)),
        ops,
    )
}

fn write_atomic_inner(
    path: &Path,
    mode: Mode,
    fill: impl FnOnce(&mut File, &Path) -> Result<(), SyncError>,
    ops: FsOps,
) -> Result<Written, SyncError> {
    let tmp = tmp_path(path);
    let mut file = open_tmp(&tmp).map_err(|e| SyncError::io(&tmp, e))?;
    let mut guard = TmpGuard {
        path: &tmp,
        armed: true,
    };

    fill(&mut file, &tmp)?;
    file.sync_all().map_err(|e| SyncError::io(&tmp, e))?;
    let tmp_meta = file.metadata().map_err(|e| SyncError::io(&tmp, e))?;

    // Bind the rename to what was written and, for `ReplaceIf`, to what it replaces. A
    // same-uid process can still swap either path between these checks and the rename; it
    // can no longer do so earlier, during the (much longer) write, undetected.
    (ops.before_checks)(&tmp, path);
    match fs::symlink_metadata(&tmp) {
        Ok(m) if m.dev() == tmp_meta.dev() && m.ino() == tmp_meta.ino() => {}
        _ => {
            tracing::warn!(tmp = %tmp.display(), "tmp file was replaced before the rename; not publishing it");
            return Err(SyncError::UnsafePackageEntry(tmp.clone()));
        }
    }
    if let Mode::ReplaceIf(expected) = mode
        && !expected.still_at(path)
    {
        tracing::warn!(path = %path.display(), "target changed since it was read; not replacing it");
        return Err(SyncError::PrimaryChangedDuringSave(path.to_owned()));
    }

    match mode {
        Mode::Replace | Mode::ReplaceIf(_) => {
            fs::rename(&tmp, path).map_err(|e| SyncError::io(path, e))?;
            guard.defuse();
        }
        // Native atomic no-replace rename first (03 §2 step 4). Only where the volume does not
        // support it, a hard link (equally atomic: `link` never replaces). If neither is
        // supported the write fails: there is no check-then-rename fallback, which could
        // clobber a file created between the check and the rename.
        Mode::NoReplace => match (ops.rename_exclusive)(&tmp, path) {
            Ok(()) => guard.defuse(),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(SyncError::AlreadyExists(path.to_owned()));
            }
            Err(e) if is_unsupported(&e) => {
                tracing::warn!(path = %path.display(), error = %e, "no-replace rename unsupported; using a hard link");
                match (ops.hard_link)(&tmp, path) {
                    // The guard now unlinks the tmp name; the data lives on under `path`.
                    Ok(()) => {}
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                        return Err(SyncError::AlreadyExists(path.to_owned()));
                    }
                    Err(e) => return Err(SyncError::io(path, e)),
                }
            }
            Err(e) => return Err(SyncError::io(path, e)),
        },
    }
    drop(guard);
    drop(file);
    let tmp_stat = Some(tmp_meta);

    // Step 5: some filesystems cannot fsync a directory (ENOTSUP, EINVAL); that alone is
    // ignored. Any other failure is reported: the rename is done, but not known durable.
    let dir = parent_dir(path);
    let synced = match take_injected_dir_sync_failure() {
        Some(e) => Err(e),
        None => (ops.sync_dir)(dir),
    };
    let dir_sync = match synced {
        Ok(()) => Ok(()),
        Err(e) if dir_sync_ignorable(&e) => {
            tracing::debug!(dir = %dir.display(), error = %e, "directory fsync unsupported; skipped");
            Ok(())
        }
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "directory fsync failed");
            Err(SyncError::io(dir, e))
        }
    };
    Ok(Written { tmp_stat, dir_sync })
}

/// Rename `src` (a file or a directory) to `dst` without ever replacing `dst`: the native
/// exclusive rename, or where the volume lacks it, for a file only, a hard link followed by
/// unlinking `src`. [`SyncError::AlreadyExists`] if `dst` exists; fails closed (no
/// check-then-rename) when neither primitive is available.
pub(crate) fn rename_no_replace(src: &Path, dst: &Path) -> Result<(), SyncError> {
    rename_no_replace_with(src, dst, REAL_FS)
}

fn rename_no_replace_with(src: &Path, dst: &Path, ops: FsOps) -> Result<(), SyncError> {
    match (ops.rename_exclusive)(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            Err(SyncError::AlreadyExists(dst.to_owned()))
        }
        Err(e) if is_unsupported(&e) && fs::symlink_metadata(src).is_ok_and(|m| m.is_file()) => {
            tracing::warn!(path = %dst.display(), error = %e, "no-replace rename unsupported; using a hard link");
            match (ops.hard_link)(src, dst) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    return Err(SyncError::AlreadyExists(dst.to_owned()));
                }
                Err(e) => return Err(SyncError::io(dst, e)),
            }
            if let Err(e) = fs::remove_file(src) {
                // `dst` holds the data; a leftover `src` is only a duplicate name.
                tracing::warn!(path = %src.display(), error = %e, "could not unlink the source after linking");
            }
            Ok(())
        }
        Err(e) => Err(SyncError::io(src, e)),
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static DIR_SYNC_FAILURES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Tests only: make the next `n` directory fsyncs on this thread fail with EIO.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn inject_dir_sync_failures(n: u32) {
    DIR_SYNC_FAILURES.with(|c| c.set(n));
}

#[cfg(any(test, feature = "test-support"))]
fn take_injected_dir_sync_failure() -> Option<std::io::Error> {
    DIR_SYNC_FAILURES.with(|c| {
        let n = c.get();
        (n > 0).then(|| {
            c.set(n - 1);
            std::io::Error::from_raw_os_error(rustix::io::Errno::IO.raw_os_error())
        })
    })
}

#[cfg(not(any(test, feature = "test-support")))]
fn take_injected_dir_sync_failure() -> Option<std::io::Error> {
    None
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

    fn enotsup(_: &Path, _: &Path) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(
            rustix::io::Errno::NOTSUP.raw_os_error(),
        ))
    }

    const NO_EXCL_RENAME: FsOps = FsOps {
        rename_exclusive: enotsup,
        ..REAL_FS
    };

    #[test]
    fn exclusive_rename_on_this_volume() {
        // The real primitive on the test volume (APFS on macOS): moves, then refuses.
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        fs::write(&a, b"a").unwrap();
        rename_exclusive(&a, &b).unwrap();
        assert!(!a.exists());
        fs::write(&a, b"a2").unwrap();
        let e = rename_exclusive(&a, &b).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{e:?}");
        assert_eq!(fs::read(&b).unwrap(), b"a");
        assert_eq!(fs::read(&a).unwrap(), b"a2");
    }

    #[test]
    fn no_replace_falls_back_to_hard_link_without_exclusive_rename() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        write_atomic_with(&target, b"ours", Mode::NoReplace, NO_EXCL_RENAME).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ours");
        assert!(leftovers(dir.path()).is_empty());

        let err = write_atomic_with(&target, b"again", Mode::NoReplace, NO_EXCL_RENAME)
            .err()
            .unwrap();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
        assert_eq!(fs::read(&target).unwrap(), b"ours");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn no_replace_fails_closed_without_any_atomic_primitive() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        let ops = FsOps {
            rename_exclusive: unsupported,
            hard_link: unsupported,
            ..REAL_FS
        };
        let err = write_atomic_with(&target, b"ours", Mode::NoReplace, ops)
            .err()
            .unwrap();
        assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
        assert!(!target.exists());
        assert!(leftovers(dir.path()).is_empty());
    }

    /// The target is created by someone else after any check could have run (inside the
    /// "rename" call itself): it is reported as `AlreadyExists` and kept.
    #[test]
    fn no_replace_keeps_a_target_created_concurrently() {
        fn racing_link(src: &Path, dst: &Path) -> std::io::Result<()> {
            fs::write(dst, b"theirs")?;
            fs::hard_link(src, dst)
        }
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        let ops = FsOps {
            rename_exclusive: enotsup,
            hard_link: racing_link,
            ..REAL_FS
        };
        let err = write_atomic_with(&target, b"ours", Mode::NoReplace, ops)
            .err()
            .unwrap();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
        assert_eq!(fs::read(&target).unwrap(), b"theirs");
        assert!(leftovers(dir.path()).is_empty());

        fn racing_rename(src: &Path, dst: &Path) -> std::io::Result<()> {
            fs::write(dst, b"theirs2")?;
            rename_exclusive(src, dst)
        }
        let target = dir.path().join("b.vault");
        let ops = FsOps {
            rename_exclusive: racing_rename,
            ..REAL_FS
        };
        let err = write_atomic_with(&target, b"ours", Mode::NoReplace, ops)
            .err()
            .unwrap();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
        assert_eq!(fs::read(&target).unwrap(), b"theirs2");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn rename_no_replace_moves_files_and_directories_and_never_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let (src, dst) = (dir.path().join("src"), dir.path().join("dst"));
        fs::create_dir(&src).unwrap();
        fs::write(src.join("f"), b"1").unwrap();
        rename_no_replace(&src, &dst).unwrap();
        assert!(dst.join("f").is_file() && !src.exists());

        fs::create_dir(&src).unwrap();
        let err = rename_no_replace(&src, &dst).unwrap_err();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
        assert!(src.exists() && dst.join("f").is_file());

        // Without the native primitive: files go through a hard link, directories fail closed.
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        fs::write(&a, b"a").unwrap();
        rename_no_replace_with(&a, &b, NO_EXCL_RENAME).unwrap();
        assert!(!a.exists());
        assert_eq!(fs::read(&b).unwrap(), b"a");
        fs::write(&a, b"a2").unwrap();
        let err = rename_no_replace_with(&a, &b, NO_EXCL_RENAME).unwrap_err();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
        assert_eq!(fs::read(&b).unwrap(), b"a");
        let err =
            rename_no_replace_with(&src, &dir.path().join("new"), NO_EXCL_RENAME).unwrap_err();
        assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
        assert!(src.exists());
    }

    /// Finding [2]: the tmp path is replaced (new inode) after the write and before the
    /// rename: nothing is published, the target keeps its bytes, no tmp is left.
    #[test]
    fn tmp_swapped_before_rename_is_not_published() {
        fn swap_tmp(tmp: &Path, _: &Path) {
            fs::remove_file(tmp).unwrap();
            fs::write(tmp, b"evil").unwrap();
        }
        fn link_tmp(tmp: &Path, _: &Path) {
            let elsewhere = tmp.with_extension("elsewhere");
            fs::write(&elsewhere, b"evil").unwrap();
            fs::remove_file(tmp).unwrap();
            std::os::unix::fs::symlink(&elsewhere, tmp).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        fs::write(&target, b"old").unwrap();
        for (swap, mode) in [
            (swap_tmp as fn(&Path, &Path), Mode::Replace),
            (link_tmp, Mode::Replace),
            (swap_tmp, Mode::NoReplace),
        ] {
            let ops = FsOps {
                before_checks: swap,
                ..REAL_FS
            };
            let err = write_atomic_with(&target, b"new", mode, ops).err().unwrap();
            assert!(matches!(err, SyncError::UnsafePackageEntry(_)), "{err:?}");
            assert_eq!(fs::read(&target).unwrap(), b"old");
            assert!(leftovers(dir.path()).is_empty());
        }
    }

    /// `ReplaceIf`: replaces only the identified version; a replacement (new inode), an
    /// in-place change or a vanished target is `PrimaryChangedDuringSave`, untouched.
    #[test]
    fn replace_if_requires_the_expected_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        fs::write(&target, b"old").unwrap();
        let id = FileId::of(&fs::symlink_metadata(&target).unwrap());
        write_atomic(&target, b"new", Mode::ReplaceIf(id)).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");

        // The id of the file just replaced no longer matches.
        let err = write_atomic(&target, b"newer", Mode::ReplaceIf(id)).unwrap_err();
        assert!(
            matches!(err, SyncError::PrimaryChangedDuringSave(_)),
            "{err:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"new");

        fn replace_target(_: &Path, target: &Path) {
            let other = target.with_extension("other");
            fs::write(&other, b"theirs").unwrap();
            fs::rename(&other, target).unwrap();
        }
        let id = FileId::of(&fs::symlink_metadata(&target).unwrap());
        let ops = FsOps {
            before_checks: replace_target,
            ..REAL_FS
        };
        let err = write_atomic_with(&target, b"ours", Mode::ReplaceIf(id), ops)
            .err()
            .unwrap();
        assert!(
            matches!(err, SyncError::PrimaryChangedDuringSave(_)),
            "{err:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"theirs");
        assert!(leftovers(dir.path()).is_empty());

        let id = FileId::of(&fs::symlink_metadata(&target).unwrap());
        fs::remove_file(&target).unwrap();
        let err = write_atomic(&target, b"ours", Mode::ReplaceIf(id)).unwrap_err();
        assert!(
            matches!(err, SyncError::PrimaryChangedDuringSave(_)),
            "{err:?}"
        );
        assert!(!target.exists());
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn dir_sync_classifier() {
        use rustix::io::Errno;
        let os = |e: Errno| std::io::Error::from_raw_os_error(e.raw_os_error());
        // std reports ENOSYS as `Unsupported`, which is ignored too.
        for e in [Errno::NOTSUP, Errno::OPNOTSUPP, Errno::INVAL, Errno::NOSYS] {
            assert!(dir_sync_ignorable(&os(e)), "{e:?}");
        }
        assert!(dir_sync_ignorable(&ErrorKind::Unsupported.into()));
        for e in [Errno::IO, Errno::NOSPC, Errno::ACCESS, Errno::ROFS] {
            assert!(!dir_sync_ignorable(&os(e)), "{e:?}");
        }
    }

    #[test]
    fn dir_sync_error_is_reported_after_the_rename() {
        fn eio(_: &Path) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(
                rustix::io::Errno::IO.raw_os_error(),
            ))
        }
        fn einval(_: &Path) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(
                rustix::io::Errno::INVAL.raw_os_error(),
            ))
        }
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.vault");
        let ops = FsOps {
            sync_dir: eio,
            ..REAL_FS
        };
        let w = write_atomic_with(&target, b"new", Mode::Replace, ops).unwrap();
        assert!(matches!(w.dir_sync, Err(SyncError::Io { .. })));
        // The rename is not rolled back.
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(leftovers(dir.path()).is_empty());

        let ops = FsOps {
            sync_dir: einval,
            ..REAL_FS
        };
        let w = write_atomic_with(&target, b"newer", Mode::Replace, ops).unwrap();
        assert!(w.dir_sync.is_ok());
    }
}
