//! iCloud eviction hooks (spec 04 §4) and iCloud Drive path detection.
//!
//! `ICloudHooks` mirrors `vault_sync::CloudHooks` with inherent methods.
//! vault-macos does not depend on vault-sync, so `vault-app` supplies the
//! trait impl as a newtype adapter.

use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

/// How often [`ICloudHooks::ensure_downloaded`] re-reads the download status.
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How often [`ICloudHooks::pin`] touches the file's access time.
pub const PIN_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Failure from [`ICloudHooks::ensure_downloaded`]. Same shape as
/// `vault_sync::CloudError`; `vault-app` maps one to the other.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CloudError {
    /// The file was not downloaded within the timeout.
    #[error("timed out waiting for iCloud to download the file")]
    Timeout,
    /// Any other provider failure.
    #[error("iCloud error: {0}")]
    Other(String),
}

/// True if `path` is inside iCloud Drive: the `NSURLIsUbiquitousItemKey`
/// resource value is true, or the path lies under `~/Library/Mobile Documents`
/// (covers files that do not exist yet).
pub fn is_in_icloud(path: &Path) -> bool {
    under_mobile_documents(path) || imp::is_ubiquitous(path)
}

fn names(path: &Path) -> Vec<&str> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect()
}

fn under_mobile_documents(path: &Path) -> bool {
    names(path)
        .windows(2)
        .any(|w| w[0] == "Library" && w[1] == "Mobile Documents")
}

struct Pin {
    path: PathBuf,
    /// Dropping the sender wakes the thread, which then exits.
    stop: Option<Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

/// iCloud implementation of the sync crate's cloud hooks.
///
/// Holds the `pin` threads; they stop when this value is dropped. If an
/// instance is leaked instead, its pin threads keep running but cannot keep
/// the process alive: Rust threads are not joined at process exit.
#[derive(Default)]
pub struct ICloudHooks {
    pins: Mutex<Vec<Pin>>,
}

impl ICloudHooks {
    pub fn new() -> Self {
        Self::default()
    }

    /// True if `path` is an iCloud placeholder (download status
    /// `NotDownloaded`). Non-ubiquitous paths and lookup errors give false.
    pub fn is_evicted(&self, path: &Path) -> bool {
        imp::is_ubiquitous(path) && imp::status(path) == Some(imp::Status::NotDownloaded)
    }

    /// Asks iCloud to download `path` and polls every 250 ms until it is
    /// `Current` or `Downloaded`, for at most `timeout`. Non-ubiquitous paths
    /// return `Ok` immediately.
    ///
    /// `Downloaded` is accepted alongside `Current`: it means a complete local
    /// copy exists, though a newer version may be on the server. Reading it is
    /// safe, because the sync layer merges whatever arrives later through the
    /// watcher, and waiting for `Current` could stall unlock while offline.
    pub fn ensure_downloaded(&self, path: &Path, timeout: Duration) -> Result<(), CloudError> {
        if !imp::is_ubiquitous(path) {
            return Ok(());
        }
        if imp::status(path).is_some_and(imp::Status::is_local) {
            return Ok(());
        }
        imp::start_download(path)?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if imp::status(path).is_some_and(imp::Status::is_local) {
                return Ok(());
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(CloudError::Timeout);
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }

    /// Best effort "keep this file local": there is no public pin API, so a
    /// background thread sets the file's access time to now, immediately and
    /// then hourly. It uses `utimensat` on the path and never opens the file,
    /// so an evicted placeholder is never materialized and the thread never
    /// blocks on a download. The modification time is left alone, so the sync
    /// watcher does not see a content change. Pinning the same path twice is
    /// a no-op.
    pub fn pin(&self, path: &Path) {
        let mut pins = self.pins.lock().unwrap_or_else(|e| e.into_inner());
        if pins.iter().any(|p| p.path == path) {
            return;
        }
        let (tx, rx) = mpsc::channel::<()>();
        let owned = path.to_path_buf();
        let spawned = std::thread::Builder::new()
            .name("vault-icloud-pin".into())
            .spawn(move || {
                loop {
                    touch_atime(&owned);
                    match rx.recv_timeout(PIN_INTERVAL) {
                        Err(RecvTimeoutError::Timeout) => continue,
                        _ => break,
                    }
                }
            });
        match spawned {
            Ok(handle) => pins.push(Pin {
                path: path.to_path_buf(),
                stop: Some(tx),
                handle: Some(handle),
            }),
            Err(e) => tracing::warn!("could not start iCloud pin thread: {e}"),
        }
    }

    /// Number of running pin threads. Test helper only.
    #[doc(hidden)]
    pub fn pinned_count(&self) -> usize {
        self.pins.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Drop for ICloudHooks {
    fn drop(&mut self) {
        let pins = std::mem::take(self.pins.get_mut().unwrap_or_else(|e| e.into_inner()));
        for mut p in pins {
            drop(p.stop.take());
            if let Some(h) = p.handle.take() {
                let _ = h.join();
            }
        }
    }
}

/// Sets atime to now via `utimensat(AT_FDCWD, path, [UTIME_NOW, UTIME_OMIT], 0)`.
/// Works on the path without opening the file, so iCloud placeholders stay
/// evicted, and the mtime is unchanged.
#[cfg(target_os = "macos")]
fn touch_atime(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    ];
    // SAFETY: `cpath` is a valid NUL-terminated string and `times` is a
    // two-element timespec array, both alive for the duration of the call.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) };
    if rc != 0 {
        tracing::debug!(
            "iCloud pin: could not touch {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
}

/// Off macOS there are no iCloud placeholders, so opening the file is fine.
/// `FileTimes` with only `accessed` set leaves the mtime unchanged.
#[cfg(not(target_os = "macos"))]
fn touch_atime(path: &Path) {
    use std::fs::{File, FileTimes};
    let res = File::open(path)
        .and_then(|f| f.set_times(FileTimes::new().set_accessed(std::time::SystemTime::now())));
    if let Err(e) = res {
        tracing::debug!("iCloud pin: could not touch {}: {e}", path.display());
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::Path;

    use objc2::rc::Retained;
    use objc2_foundation::{
        NSArray, NSFileManager, NSNumber, NSString, NSURL, NSURLIsUbiquitousItemKey,
        NSURLResourceKey, NSURLUbiquitousItemDownloadingStatusCurrent,
        NSURLUbiquitousItemDownloadingStatusDownloaded, NSURLUbiquitousItemDownloadingStatusKey,
        NSURLUbiquitousItemDownloadingStatusNotDownloaded,
    };

    use super::CloudError;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Status {
        NotDownloaded,
        Downloaded,
        Current,
    }

    impl Status {
        pub fn is_local(self) -> bool {
            matches!(self, Status::Downloaded | Status::Current)
        }
    }

    /// A fresh NSURL each call, so no cached resource values are reused.
    fn url(path: &Path) -> Option<Retained<NSURL>> {
        let s = path.to_str()?;
        Some(NSURL::fileURLWithPath(&NSString::from_str(s)))
    }

    fn resource(
        path: &Path,
        key: &NSURLResourceKey,
    ) -> Option<Retained<objc2::runtime::AnyObject>> {
        let url = url(path)?;
        let keys = NSArray::from_slice(&[key]);
        url.resourceValuesForKeys_error(&keys)
            .ok()?
            .objectForKey(key)
    }

    pub fn is_ubiquitous(path: &Path) -> bool {
        // SAFETY: reading an immutable Foundation constant.
        let key = unsafe { NSURLIsUbiquitousItemKey };
        resource(path, key)
            .and_then(|v| v.downcast::<NSNumber>().ok())
            .is_some_and(|n| n.boolValue())
    }

    pub fn status(path: &Path) -> Option<Status> {
        // SAFETY: reading immutable Foundation constants.
        let (key, not_dl, dl, current) = unsafe {
            (
                NSURLUbiquitousItemDownloadingStatusKey,
                NSURLUbiquitousItemDownloadingStatusNotDownloaded,
                NSURLUbiquitousItemDownloadingStatusDownloaded,
                NSURLUbiquitousItemDownloadingStatusCurrent,
            )
        };
        let v = resource(path, key)?.downcast::<NSString>().ok()?;
        if *v == *not_dl {
            Some(Status::NotDownloaded)
        } else if *v == *dl {
            Some(Status::Downloaded)
        } else if *v == *current {
            Some(Status::Current)
        } else {
            None
        }
    }

    pub fn start_download(path: &Path) -> Result<(), CloudError> {
        let url = url(path).ok_or_else(|| CloudError::Other("path is not UTF-8".into()))?;
        NSFileManager::defaultManager()
            .startDownloadingUbiquitousItemAtURL_error(&url)
            .map_err(|e| CloudError::Other(e.localizedDescription().to_string()))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    //! No iCloud off macOS: nothing is ubiquitous.
    use std::path::Path;

    use super::CloudError;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Status {
        NotDownloaded,
        Downloaded,
        Current,
    }

    impl Status {
        pub fn is_local(self) -> bool {
            matches!(self, Status::Downloaded | Status::Current)
        }
    }

    pub fn is_ubiquitous(_path: &Path) -> bool {
        false
    }

    pub fn status(_path: &Path) -> Option<Status> {
        None
    }

    pub fn start_download(_path: &Path) -> Result<(), CloudError> {
        Ok(())
    }
}
