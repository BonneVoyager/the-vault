//! Cloud hooks around conflict copies (03 §7): `ensure_downloaded` before reading a conflicted
//! copy, the default timeout, and the retry on the next watcher event after a timeout.
//!
//! The double [`Provider`] models an iCloud/File Provider placeholder: an evicted file exists
//! locally as a dataless stub (zeros here) until `ensure_downloaded` materialises the real
//! bytes. A read that skipped the download would see the stub, never the vault.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::{Item, KdfParams, SecretString, Uuid};
use vault_sync::{
    CloudError, CloudHooks, DEBOUNCE, DOWNLOAD_TIMEOUT, NoopHooks, SyncEvent, SyncedVault,
    VAULT_FILE_NAME,
};

const T0: u64 = 1_700_000_000_000;
const DEADLINE: Duration = Duration::from_secs(20);
const DEV_A: Uuid = Uuid::from_u128(0xA);
const DEV_B: Uuid = Uuid::from_u128(0xB);
const STUB: &[u8] = &[0; 512];

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

/// `(parent dir name, file name)`: FSEvents may spell the same path under `/private/var`,
/// so files are matched by their last two components.
type Tail = (String, String);

fn tail(p: &Path) -> Option<Tail> {
    let name = p.file_name()?.to_string_lossy().into_owned();
    let parent = p.parent()?.file_name()?.to_string_lossy().into_owned();
    Some((parent, name))
}

/// Evicted files and their real content; `fail` makes every download of one time out.
#[derive(Default)]
struct Provider {
    evicted: Mutex<HashMap<Tail, Vec<u8>>>,
    fail: AtomicBool,
    /// Every `ensure_downloaded` call for an evicted (or formerly evicted) file.
    calls: Mutex<Vec<Tail>>,
    watched: Mutex<Vec<Tail>>,
}

impl Provider {
    fn evict(&self, path: &Path, real: Vec<u8>) {
        let t = tail(path).unwrap();
        self.watched.lock().unwrap().push(t.clone());
        self.evicted.lock().unwrap().insert(t, real);
    }
    /// The provider finished the download on its own: the file is no longer evicted.
    fn settle(&self, path: &Path) -> Vec<u8> {
        self.evicted
            .lock()
            .unwrap()
            .remove(&tail(path).unwrap())
            .unwrap()
    }
    fn calls_for(&self, path: &Path) -> usize {
        let t = tail(path).unwrap();
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == t)
            .count()
    }
}

impl CloudHooks for Provider {
    fn is_evicted(&self, path: &Path) -> bool {
        tail(path).is_some_and(|t| self.evicted.lock().unwrap().contains_key(&t))
    }
    fn ensure_downloaded(&self, path: &Path, timeout: Duration) -> Result<(), CloudError> {
        assert_eq!(timeout, DOWNLOAD_TIMEOUT);
        let Some(t) = tail(path) else { return Ok(()) };
        if self.watched.lock().unwrap().contains(&t) {
            self.calls.lock().unwrap().push(t.clone());
        }
        let mut evicted = self.evicted.lock().unwrap();
        let Some(real) = evicted.get(&t) else {
            return Ok(());
        };
        if self.fail.load(Ordering::SeqCst) {
            return Err(CloudError::Timeout);
        }
        plant(path, real);
        evicted.remove(&t);
        Ok(())
    }
    fn pin(&self, _path: &Path) {}
}

/// Write `bytes` at `dst` via a hidden tmp name and a rename.
fn plant(dst: &Path, bytes: &[u8]) {
    let tmp = dst.with_file_name(".planting.tmp");
    fs::write(&tmp, bytes).unwrap();
    fs::rename(&tmp, dst).unwrap();
}

/// Device A (on `provider`) holds "mail"; B's unsaved state adds "from b". Returns the dir,
/// A's package, A, and B's serialized vault (the conflicted copy's real content).
fn setup(provider: &Arc<Provider>) -> (TempDir, PathBuf, SyncedVault, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join("test.vault");
    let mut a = SyncedVault::create(
        &package,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        provider.clone(),
    )
    .unwrap();
    a.edit(|v| v.insert(Item::new("mail", Uuid::nil(), T0), T0))
        .unwrap();
    a.save().unwrap();
    let mut b = SyncedVault::open(&package, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let theirs = b.vault().unwrap().serialize();
    (dir, package, a, theirs)
}

/// An evicted conflicted copy: a whole sibling package (iCloud) or a per-file copy inside
/// ours (Dropbox). Returns the evicted vault file.
fn plant_evicted_copy(
    provider: &Provider,
    dir: &Path,
    package: &Path,
    per_file: bool,
    real: Vec<u8>,
) -> PathBuf {
    let inner = if per_file {
        package.join("vault 2.bin")
    } else {
        let copy = dir.join("test 2.vault");
        fs::create_dir(&copy).unwrap();
        copy.join(VAULT_FILE_NAME)
    };
    provider.evict(&inner, real);
    plant(&inner, STUB);
    inner
}

fn titles(v: &SyncedVault) -> Vec<String> {
    let mut t: Vec<String> = v
        .vault()
        .unwrap()
        .items()
        .map(|i| i.title.clone())
        .collect();
    t.sort();
    t
}

fn wait_for(
    v: &mut SyncedVault,
    rx: &Receiver<SyncEvent>,
    seen: &mut Vec<SyncEvent>,
    f: impl Fn(&SyncEvent) -> bool,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        v.poll();
        seen.extend(rx.try_iter());
        if seen.iter().any(&f) {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn absorbed(e: &SyncEvent) -> bool {
    matches!(e, SyncEvent::ConflictAbsorbed(_))
}

fn bad(e: &SyncEvent) -> bool {
    matches!(e, SyncEvent::CorruptOnDisk | SyncEvent::Error(_))
}

/// 03 §7-6.
#[test]
fn default_download_timeout_is_30_seconds() {
    assert_eq!(DOWNLOAD_TIMEOUT, Duration::from_secs(30));
}

/// 03 §7-3: the conflicted copy is downloaded before it is read; only the downloaded bytes
/// (never the stub) can produce the merge.
#[test]
fn evicted_conflict_copy_is_downloaded_before_reading() {
    for per_file in [false, true] {
        let provider = Arc::new(Provider::default());
        let (dir, package, mut a, theirs) = setup(&provider);
        let inner = plant_evicted_copy(&provider, dir.path(), &package, per_file, theirs);
        let rx = a.subscribe();
        let mut seen = Vec::new();
        a.start_watching().unwrap();
        assert!(
            wait_for(&mut a, &rx, &mut seen, absorbed),
            "per_file={per_file}: {seen:?}"
        );
        assert!(provider.calls_for(&inner) >= 1);
        assert!(!provider.is_evicted(&inner));
        assert_eq!(titles(&a), ["from b", "mail"], "per_file={per_file}");
        assert!(!seen.iter().any(bad), "per_file={per_file}: {seen:?}");
    }
}

/// 03 §7-3: a failed download of a conflicted copy is `CloudUnavailable`, never a corrupt
/// file or an error, and the copy stays where it is.
#[test]
fn conflict_copy_download_failure_is_cloud_unavailable() {
    for per_file in [false, true] {
        let provider = Arc::new(Provider::default());
        provider.fail.store(true, Ordering::SeqCst);
        let (dir, package, mut a, theirs) = setup(&provider);
        let inner = plant_evicted_copy(&provider, dir.path(), &package, per_file, theirs);
        let rx = a.subscribe();
        let mut seen = Vec::new();
        a.start_watching().unwrap();
        assert!(
            wait_for(&mut a, &rx, &mut seen, |e| *e
                == SyncEvent::CloudUnavailable),
            "per_file={per_file}: {seen:?}"
        );
        assert!(provider.calls_for(&inner) >= 1);
        assert!(!seen.iter().any(bad), "per_file={per_file}: {seen:?}");
        assert!(!seen.iter().any(absorbed));
        assert_eq!(fs::read(&inner).unwrap(), STUB, "copy moved or rewritten");
        assert_eq!(titles(&a), ["mail"]);
        assert!(!a.is_dirty());
    }
}

/// 03 §7-7: after a timed-out download, the next watcher event for the copy retries the read,
/// which succeeds once the provider has the file.
#[test]
fn cloud_unavailable_conflict_is_retried_on_the_next_watcher_event() {
    let provider = Arc::new(Provider::default());
    provider.fail.store(true, Ordering::SeqCst);
    let (dir, package, mut a, theirs) = setup(&provider);
    let inner = plant_evicted_copy(&provider, dir.path(), &package, false, theirs);
    let rx = a.subscribe();
    let mut seen = Vec::new();
    a.start_watching().unwrap();
    assert!(wait_for(&mut a, &rx, &mut seen, |e| *e
        == SyncEvent::CloudUnavailable));
    // Let any events from setup settle.
    let quiet = |a: &mut SyncedVault, windows: u32| {
        let until = Instant::now() + DEBOUNCE * windows;
        while Instant::now() < until {
            a.poll();
            thread::sleep(Duration::from_millis(25));
        }
    };
    quiet(&mut a, 3);
    let first = provider.calls_for(&inner);
    assert!(first >= 1);
    // Without a new watcher event nothing is retried.
    quiet(&mut a, 2);
    assert_eq!(
        provider.calls_for(&inner),
        first,
        "retried without an event"
    );
    seen.extend(rx.try_iter());
    assert!(!seen.iter().any(absorbed));

    // The provider finishes the download in the background; materialising the file is the
    // next watcher event.
    provider.fail.store(false, Ordering::SeqCst);
    let real = provider.settle(&inner);
    plant(&inner, &real);
    assert!(wait_for(&mut a, &rx, &mut seen, absorbed), "{seen:?}");
    assert!(
        provider.calls_for(&inner) > first,
        "read not retried through ensure_downloaded"
    );
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!dir.path().join("test 2.vault").exists());
    assert!(!seen.iter().any(bad), "{seen:?}");
}
