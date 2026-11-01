//! iCloud hooks and iCloud Drive path detection (spec 04 §4, §8).

use std::fs::{File, FileTimes};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use vault_macos::{ICloudHooks, is_in_icloud};

#[test]
fn non_ubiquitous_temp_path_is_not_evicted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.vault");
    std::fs::write(&path, b"x").unwrap();
    let hooks = ICloudHooks::new();
    assert!(!hooks.is_evicted(&path));
    assert!(!is_in_icloud(&path));
    // Missing files are not evicted either.
    assert!(!hooks.is_evicted(&dir.path().join("missing.vault")));
}

#[test]
fn ensure_downloaded_on_local_path_is_immediate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.vault");
    std::fs::write(&path, b"x").unwrap();
    // Generous timeout so a loaded machine cannot fail this; the intent is only that a
    // local file returns Ok without waiting out the timeout.
    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    ICloudHooks::new()
        .ensure_downloaded(&path, timeout)
        .expect("local file must report downloaded");
    let elapsed = start.elapsed();
    assert!(
        elapsed < timeout / 3,
        "ensure_downloaded waited {elapsed:?} on a local path (timeout {timeout:?})"
    );
}

#[test]
fn mobile_documents_path_is_icloud() {
    assert!(is_in_icloud(Path::new(
        "/Users/x/Library/Mobile Documents/com~apple~CloudDocs/a.vault"
    )));
}

#[test]
fn missing_temp_path_is_not_icloud() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!is_in_icloud(&dir.path().join("a.vault")));
}

#[test]
fn pin_touches_atime_only_and_stops_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.vault");
    std::fs::write(&path, b"x").unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(FileTimes::new().set_accessed(old).set_modified(old))
        .unwrap();

    let hooks = ICloudHooks::new();
    hooks.pin(&path);
    hooks.pin(&path);
    assert_eq!(hooks.pinned_count(), 1);

    // The thread touches immediately on start.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let meta = std::fs::metadata(&path).unwrap();
        if meta.accessed().unwrap() > old {
            assert_eq!(meta.modified().unwrap(), old, "mtime must not change");
            break;
        }
        assert!(Instant::now() < deadline, "pin thread never touched atime");
        std::thread::sleep(Duration::from_millis(10));
    }

    let start = Instant::now();
    drop(hooks);
    assert!(start.elapsed() < Duration::from_secs(1));
}
