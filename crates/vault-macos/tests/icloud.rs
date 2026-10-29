//! iCloud hooks and provider detection (spec 04 §4, §8).

use std::fs::{File, FileTimes};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use vault_macos::{CloudProvider, ICloudHooks, cloud_provider, is_in_icloud};

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
    let start = Instant::now();
    ICloudHooks::new()
        .ensure_downloaded(&path, Duration::from_secs(5))
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn provider_classification() {
    assert_eq!(
        cloud_provider(Path::new(
            "/Users/x/Library/Mobile Documents/com~apple~CloudDocs/a.vault"
        )),
        CloudProvider::ICloud
    );
    assert_eq!(
        cloud_provider(Path::new("/Users/x/Dropbox/a.vault")),
        CloudProvider::Dropbox
    );
    assert_eq!(
        cloud_provider(Path::new(
            "/Users/x/Library/CloudStorage/Dropbox-Personal/a.vault"
        )),
        CloudProvider::Dropbox
    );
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        cloud_provider(&dir.path().join("a.vault")),
        CloudProvider::Local
    );
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
