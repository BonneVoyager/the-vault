//! Advisory lock on `<name>.vault/.lock` (03 §2, V-02).
//!
//! `save` holds an exclusive lock from the pre-write merge's read until after the rename and
//! the directory fsync, so two processes (the app and the CLI, or two CLI commands) cannot
//! interleave a read-modify-write and lose items. `open` takes a shared lock around its read
//! of `vault.bin`. The lock is `flock(2)` through `std::fs::File::lock*` (no extra crate); it
//! belongs to the open file description, so two `SyncedVault`s in one process exclude each
//! other too. Dropping the guard closes the descriptor, which releases the lock.
//!
//! The lock file is empty, mode 0600, created on first use and never deleted (deleting it
//! would let a second locker lock a fresh inode while the first still holds the old one).
//!
//! Volumes without `flock` (some SMB/NFS mounts: ENOTSUP, EOPNOTSUPP, ENOLCK) get a no-op
//! guard and one warning per process: saving must keep working there, only unprotected
//! against a concurrent writer. ENOLCK can also be transient on NFS (lock daemon briefly
//! unavailable); that save then silently runs without the lock too. A lock file that cannot
//! be opened for lack of permission (EACCES, EPERM, EROFS, or ENOENT in a read-only package
//! that has none) also means "no lock", logged at warn for a write. Every other open error
//! (EMFILE, ENOSPC, a directory named `.lock`, EIO, ...) fails the save or open.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, ErrorKind};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::SyncError;
use crate::package;

/// How long a save (or open) waits for another holder before giving up with
/// [`SyncError::SaveLockTimeout`].
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Holds the lock until dropped. `None` inside: no lock could be taken on this volume (see
/// the module docs) and the guard does nothing.
#[derive(Debug)]
pub(crate) struct PackageLock {
    _file: Option<File>,
}

impl PackageLock {
    /// Exclusive lock for a write of the primary. [`SyncError::SaveLockTimeout`] after
    /// [`LOCK_TIMEOUT`]; an I/O fault on the lock file is an error; a volume without locking
    /// yields a no-op guard.
    pub(crate) fn exclusive(package: &Path) -> Result<Self, SyncError> {
        Self::take(package, true)
    }

    /// Shared lock for a read of the primary; same rules as [`PackageLock::exclusive`].
    pub(crate) fn shared(package: &Path) -> Result<Self, SyncError> {
        Self::take(package, false)
    }

    fn take(package: &Path, exclusive: bool) -> Result<Self, SyncError> {
        let path = package::lock_file(package);
        let Some(file) = open_lock_file(&path, exclusive)? else {
            return Ok(Self { _file: None });
        };
        acquire(file, &path, exclusive, LOCK_TIMEOUT, |f, x| {
            if x { f.try_lock() } else { f.try_lock_shared() }
        })
    }
}

/// The lock file opened read-write (created 0600), else read-only (a read-only location
/// with an existing lock file still shares locks with writers elsewhere). `Ok(None)` only
/// when permissions forbid both (see the module docs); every other error is returned.
fn open_lock_file(path: &Path, exclusive: bool) -> Result<Option<File>, SyncError> {
    let err = match open_rw(path) {
        Ok(f) => return Ok(Some(f)),
        Err(e) if is_permission(&e) => e,
        Err(e) => return Err(SyncError::io(path, e)),
    };
    match File::open(path) {
        Ok(f) => Ok(Some(f)),
        // Not writable, and either unreadable or absent (read-only package without one).
        Err(e) if is_permission(&e) || e.kind() == ErrorKind::NotFound => {
            if exclusive {
                tracing::warn!(path = %path.display(), create_error = %err, open_error = %e, "cannot open the vault lock file; saving without the lock");
            } else {
                tracing::debug!(path = %path.display(), create_error = %err, open_error = %e, "cannot open the vault lock file; reading without the lock");
            }
            Ok(None)
        }
        Err(e) => Err(SyncError::io(path, e)),
    }
}

/// EACCES and EPERM (both `PermissionDenied`) or EROFS.
fn is_permission(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
    )
}

#[cfg(test)]
const EIO: i32 = 5;
#[cfg(target_os = "macos")]
const ENOLCK: i32 = 77;
#[cfg(target_os = "macos")]
const ENOTSUP: i32 = 45;
#[cfg(target_os = "macos")]
const EOPNOTSUPP: i32 = 102;
#[cfg(not(target_os = "macos"))]
const ENOLCK: i32 = 37;
#[cfg(not(target_os = "macos"))]
const ENOTSUP: i32 = 95;
#[cfg(not(target_os = "macos"))]
const EOPNOTSUPP: i32 = 95;

/// The filesystem cannot lock at all (as opposed to a lock held by someone else).
fn is_unsupported(e: &io::Error) -> bool {
    e.kind() == ErrorKind::Unsupported
        || matches!(e.raw_os_error(), Some(c) if c == ENOLCK || c == ENOTSUP || c == EOPNOTSUPP)
}

static WARNED_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

/// Test-only count of "locking unavailable" warnings actually logged (03 §2: once per
/// process). The crate has no log-capture support, so tests observe this instead.
#[cfg(test)]
static UNSUPPORTED_WARNINGS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn open_rw(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
}

/// Poll `try_lock` with a growing back-off (1 ms to 50 ms) until `timeout`. Polling instead of
/// a blocking `flock` keeps the timeout without a helper thread or signals.
/// `try_lock` is injectable so tests can simulate a volume without locking.
fn acquire(
    file: File,
    path: &Path,
    exclusive: bool,
    timeout: Duration,
    mut try_lock: impl FnMut(&File, bool) -> Result<(), TryLockError>,
) -> Result<PackageLock, SyncError> {
    let deadline = Instant::now() + timeout;
    let mut wait = Duration::from_millis(1);
    loop {
        match try_lock(&file, exclusive) {
            Ok(()) => return Ok(PackageLock { _file: Some(file) }),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) if e.kind() == ErrorKind::Interrupted => continue,
            Err(TryLockError::Error(e)) if is_unsupported(&e) => {
                if !WARNED_UNSUPPORTED.swap(true, Ordering::Relaxed) {
                    #[cfg(test)]
                    UNSUPPORTED_WARNINGS.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(path = %path.display(), error = %e, "file locking unavailable on this volume; concurrent writers are not protected");
                }
                return Ok(PackageLock { _file: None });
            }
            Err(TryLockError::Error(e)) => return Err(SyncError::io(path, e)),
        }
        let now = Instant::now();
        if now >= deadline {
            tracing::warn!(path = %path.display(), exclusive, "timed out waiting for the vault lock");
            return Err(SyncError::SaveLockTimeout(PathBuf::from(path)));
        }
        thread::sleep(wait.min(deadline - now));
        wait = (wait * 2).min(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real(f: &File, x: bool) -> Result<(), TryLockError> {
        if x { f.try_lock() } else { f.try_lock_shared() }
    }

    fn try_acquire(dir: &Path, exclusive: bool) -> Result<PackageLock, SyncError> {
        let path = package::lock_file(dir);
        let file = open_rw(&path).unwrap();
        acquire(file, &path, exclusive, Duration::from_millis(30), real)
    }

    /// Serialises the tests that drive the "locking unsupported" fallback (shared
    /// `WARNED_UNSUPPORTED` / `UNSUPPORTED_WARNINGS`). A poisoned lock is still a lock.
    fn unsupported_lock_serial() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn exclusive_excludes_and_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let held = PackageLock::exclusive(dir.path()).unwrap();
        assert!(held._file.is_some());
        let err = try_acquire(dir.path(), true).unwrap_err();
        assert!(matches!(err, SyncError::SaveLockTimeout(_)), "{err:?}");
        assert!(try_acquire(dir.path(), false).is_err());
        drop(held);
        try_acquire(dir.path(), true).unwrap();
    }

    #[test]
    fn shared_locks_coexist_and_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let a = PackageLock::shared(dir.path()).unwrap();
        let b = PackageLock::shared(dir.path()).unwrap();
        let path = package::lock_file(dir.path());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(try_acquire(dir.path(), true).is_err());
        drop((a, b));
    }

    #[test]
    fn read_only_dir_without_lock_file_proceeds_unlocked() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        let shared = PackageLock::shared(&ro);
        let exclusive = PackageLock::exclusive(&ro);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(shared.unwrap()._file.is_none());
        assert!(exclusive.unwrap()._file.is_none());
    }

    #[test]
    fn unreadable_lock_file_gives_a_no_op_guard_other_errors_fail() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = package::lock_file(dir.path());
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let exclusive = PackageLock::exclusive(dir.path());
        let shared = PackageLock::shared(dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(exclusive.unwrap()._file.is_none());
        assert!(shared.unwrap()._file.is_none());

        // A directory in its place is not a permission problem: error, never unlocked.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let err = PackageLock::exclusive(dir.path()).unwrap_err();
        assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
        assert!(PackageLock::shared(dir.path()).is_err());
    }

    #[test]
    fn interrupted_try_lock_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let path = package::lock_file(dir.path());
        let file = open_rw(&path).unwrap();
        let mut calls = 0;
        let guard = acquire(file, &path, true, LOCK_TIMEOUT, |f, x| {
            calls += 1;
            if calls == 1 {
                Err(TryLockError::Error(ErrorKind::Interrupted.into()))
            } else {
                real(f, x)
            }
        })
        .unwrap();
        assert!(guard._file.is_some());
        assert_eq!(calls, 2);
    }

    #[test]
    fn volume_without_locking_gets_a_no_op_guard() {
        let _serial = unsupported_lock_serial();
        let dir = tempfile::tempdir().unwrap();
        let path = package::lock_file(dir.path());
        let unsupported = [
            io::Error::from(ErrorKind::Unsupported),
            io::Error::from_raw_os_error(ENOLCK),
            io::Error::from_raw_os_error(ENOTSUP),
            io::Error::from_raw_os_error(EOPNOTSUPP),
        ];
        for e in unsupported {
            for exclusive in [true, false] {
                let kind = e.kind();
                let raw = e.raw_os_error();
                let file = open_rw(&path).unwrap();
                let mut e = Some(io::Error::new(kind, "x"));
                if let Some(code) = raw {
                    e = Some(io::Error::from_raw_os_error(code));
                }
                let guard = acquire(file, &path, exclusive, LOCK_TIMEOUT, |_, _| {
                    Err(TryLockError::Error(e.take().unwrap()))
                })
                .unwrap();
                assert!(guard._file.is_none());
            }
        }
        // A real I/O fault is still an error.
        let file = open_rw(&path).unwrap();
        let err = acquire(file, &path, true, LOCK_TIMEOUT, |_, _| {
            Err(TryLockError::Error(io::Error::from_raw_os_error(EIO)))
        })
        .unwrap_err();
        assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
    }

    /// 03 §2-11: the fallback warning is logged once per process, however many saves and
    /// opens hit an unlockable volume. The flag and counter are process-global and
    /// `volume_without_locking_gets_a_no_op_guard` may log first; both tests hold
    /// [`unsupported_lock_serial`], so the other test's warning is never half-done (flag set,
    /// counter not yet bumped) when this one reads it. Only "exactly one" is asserted, never
    /// which test logged it.
    #[test]
    fn lock_fallback_warning_is_logged_once() {
        let _serial = unsupported_lock_serial();
        let dir = tempfile::tempdir().unwrap();
        let path = package::lock_file(dir.path());
        for exclusive in [true, false, true, true] {
            let file = open_rw(&path).unwrap();
            let guard = acquire(file, &path, exclusive, LOCK_TIMEOUT, |_, _| {
                Err(TryLockError::Error(io::Error::from_raw_os_error(ENOTSUP)))
            })
            .unwrap();
            assert!(guard._file.is_none());
        }
        assert!(WARNED_UNSUPPORTED.load(Ordering::Relaxed));
        assert_eq!(UNSUPPORTED_WARNINGS.load(Ordering::Relaxed), 1);
    }
}
