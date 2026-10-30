//! Concurrent writers (V-02 save lock), the echo fingerprint on coarse timestamps (V-05),
//! `lock()` preserving unsaved edits (V-06, 03 §8) and stale vault tmp cleanup (03 §1).

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use vault_core::{Item, KdfParams, LockedVault, SecretString, Uuid};
use vault_sync::{
    BackupKind, CloudError, CloudHooks, NoopHooks, SyncEvent, SyncedVault, VAULT_FILE_NAME,
};

const T0: u64 = 1_700_000_000_000;
const DEV_A: Uuid = Uuid::from_u128(0xA);
const DEV_B: Uuid = Uuid::from_u128(0xB);
const PER_WRITER: usize = 10;

/// Env vars that turn [`child_writer`] from a no-op into a writer process.
const CHILD_PKG: &str = "VAULT_SYNC_TEST_CHILD_PKG";
const CHILD_TAG: &str = "VAULT_SYNC_TEST_CHILD_TAG";
const CHILD_GO: &str = "VAULT_SYNC_TEST_CHILD_GO";

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn create() -> (TempDir, PathBuf, SyncedVault) {
    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join("test.vault");
    let v = SyncedVault::create(
        &package,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        Arc::new(NoopHooks),
    )
    .unwrap();
    (dir, package, v)
}

fn open_unlocked(package: &Path, device: Uuid) -> SyncedVault {
    let mut v = SyncedVault::open(package, device, Arc::new(NoopHooks)).unwrap();
    v.unlock(&pw()).unwrap();
    v
}

fn insert(v: &mut SyncedVault, title: &str) -> Uuid {
    v.edit(|vault| vault.insert(Item::new(title, Uuid::nil(), T0), T0))
        .unwrap()
}

fn titles(v: &SyncedVault) -> BTreeSet<String> {
    v.vault()
        .unwrap()
        .items()
        .map(|i| i.title.clone())
        .collect()
}

/// Insert and save `PER_WRITER` items one at a time, so every save races the other writer.
fn write_items(v: &mut SyncedVault, tag: &str) {
    for n in 0..PER_WRITER {
        insert(v, &format!("{tag}-{n}"));
        v.save().unwrap();
    }
}

fn expected(tags: &[&str]) -> BTreeSet<String> {
    tags.iter()
        .flat_map(|t| (0..PER_WRITER).map(move |n| format!("{t}-{n}")))
        .collect()
}

#[test]
fn concurrent_saves_from_two_threads_lose_nothing() {
    for round in 0..5 {
        let (_dir, package, creator) = create();
        drop(creator);
        let barrier = Arc::new(Barrier::new(2));
        let writers: Vec<_> = [("a", DEV_A), ("b", DEV_B)]
            .into_iter()
            .map(|(tag, device)| {
                let package = package.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut v = open_unlocked(&package, device);
                    barrier.wait();
                    write_items(&mut v, tag);
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let v = open_unlocked(&package, Uuid::nil());
        assert_eq!(titles(&v), expected(&["a", "b"]), "round {round}");
    }
}

/// Not a test of its own: the body of a writer process for
/// [`concurrent_saves_from_two_processes_lose_nothing`], which re-runs this test binary with
/// `--ignored --exact child_writer` and the env vars set. A no-op otherwise.
#[test]
#[ignore = "helper process for concurrent_saves_from_two_processes_lose_nothing"]
fn child_writer() {
    let (Some(package), Some(tag), Some(go)) = (
        std::env::var_os(CHILD_PKG),
        std::env::var(CHILD_TAG).ok(),
        std::env::var_os(CHILD_GO),
    ) else {
        return;
    };
    let device = Uuid::from_u128(u128::from(tag.as_bytes()[0]));
    let mut v = open_unlocked(Path::new(&package), device);
    // Start together: the parent creates `go` once both children are running.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !Path::new(&go).exists() {
        assert!(Instant::now() < deadline, "parent never said go");
        thread::sleep(Duration::from_millis(1));
    }
    write_items(&mut v, &tag);
}

#[test]
fn concurrent_saves_from_two_processes_lose_nothing() {
    let exe = std::env::current_exe().unwrap();
    for round in 0..5 {
        let (dir, package, creator) = create();
        drop(creator);
        let go = dir.path().join("go");
        let children: Vec<_> = ["p", "q"]
            .into_iter()
            .map(|tag| {
                Command::new(&exe)
                    .args(["--ignored", "--exact", "child_writer", "--test-threads=1"])
                    .env(CHILD_PKG, &package)
                    .env(CHILD_TAG, tag)
                    .env(CHILD_GO, &go)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        // Give both children time to unlock, then release them at once.
        thread::sleep(Duration::from_millis(300));
        fs::write(&go, b"").unwrap();
        for c in children {
            let out = c.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "child failed: {}\n{}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let v = open_unlocked(&package, Uuid::nil());
        assert_eq!(titles(&v), expected(&["p", "q"]), "round {round}");
    }
}

/// V-05: a peer rewrites `vault.bin` in place with the same size and the same mtime (a
/// coarse-timestamp filesystem). Only ctime tells; the pre-write merge must still read it.
#[test]
fn same_size_same_mtime_rewrite_is_still_read() {
    let (_dir, package, mut a) = create();
    let id = insert(&mut a, "one");
    a.save().unwrap();
    let file = package.join(VAULT_FILE_NAME);
    let before = fs::metadata(&file).unwrap();

    let mut b = open_unlocked(&package, DEV_B);
    b.edit(|v| v.update(id, T0 + 10, |item| item.title = "two".to_owned()))
        .unwrap()
        .unwrap();
    let theirs = b.vault().unwrap().serialize();
    assert_eq!(
        theirs.len() as u64,
        before.len(),
        "test needs a same-size write"
    );

    // In place (same inode), then put the old mtime back.
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&file)
        .unwrap();
    f.write_all(&theirs).unwrap();
    f.set_modified(before.modified().unwrap()).unwrap();
    drop(f);
    let after = fs::metadata(&file).unwrap();
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(after.len(), before.len());

    // A dirty save must merge B's version first instead of writing over it.
    a.edit(|_| ()).unwrap();
    a.save().unwrap();
    assert_eq!(titles(&a), BTreeSet::from(["two".to_owned()]));
    let reopened = open_unlocked(&package, Uuid::nil());
    assert_eq!(titles(&reopened), BTreeSet::from(["two".to_owned()]));
}

fn unsaved_backups(v: &SyncedVault) -> Vec<PathBuf> {
    v.backups()
        .unwrap()
        .into_iter()
        .filter(|b| b.kind == BackupKind::Unsaved)
        .map(|b| b.path)
        .collect()
}

/// V-06: locking a dirty vault snapshots it to an `Unsaved` backup first (03 §8).
#[test]
fn lock_while_dirty_preserves_the_edit_in_an_unsaved_backup() {
    let (_dir, _package, mut v) = create();
    insert(&mut v, "saved");
    v.save().unwrap();
    insert(&mut v, "never saved");
    let events = v.subscribe();
    v.lock();

    let unsaved = unsaved_backups(&v);
    assert_eq!(unsaved.len(), 1, "{unsaved:?}");
    let got: Vec<SyncEvent> = events.try_iter().collect();
    assert_eq!(got, [SyncEvent::BackupTaken(unsaved[0].clone())]);
    let backup = LockedVault::parse(&fs::read(&unsaved[0]).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    let in_backup: BTreeSet<String> = backup.items().map(|i| i.title.clone()).collect();
    assert_eq!(
        in_backup,
        BTreeSet::from(["saved".to_owned(), "never saved".to_owned()])
    );
    // The primary is untouched: the edit lives only in the backup.
    v.unlock(&pw()).unwrap();
    assert_eq!(titles(&v), BTreeSet::from(["saved".to_owned()]));
}

/// The app's path (save, then lock) leaves no `Unsaved` backup.
#[test]
fn save_then_lock_takes_no_unsaved_backup() {
    let (_dir, _package, mut v) = create();
    insert(&mut v, "x");
    v.save().unwrap();
    let events = v.subscribe();
    v.lock();
    assert!(unsaved_backups(&v).is_empty());
    assert_eq!(events.try_iter().count(), 0);
    // Clean and never edited: same.
    v.unlock(&pw()).unwrap();
    v.lock();
    assert!(unsaved_backups(&v).is_empty());
}

/// A crash between tmp creation and rename leaves `.vault.bin.tmp-*`; it is deleted once
/// older than 1 h, and only while unlocked (03 §1.1): after an unlock from locked and after a
/// save, never at open.
#[test]
fn stale_vault_tmp_is_removed_only_while_unlocked() {
    let (_dir, package, v) = create();
    drop(v);
    let stale = package.join(".vault.bin.tmp-0badf00d");
    let lock_file = package.join(".lock");
    let two_hours = Duration::from_secs(2 * 60 * 60);

    // Unlock: young files stay, old ones go.
    fs::write(&stale, b"half a vault").unwrap();
    let mut v = SyncedVault::open(&package, DEV_A, Arc::new(NoopHooks)).unwrap();
    v.unlock(&pw()).unwrap();
    assert!(stale.exists(), "younger than 1 h must stay");
    v.lock();
    v.set_prune_clock_offset_for_tests(two_hours);
    v.backups().unwrap();
    assert!(stale.exists(), "nothing is cleaned while locked");
    v.unlock(&pw()).unwrap();
    assert!(!stale.exists(), "removed at unlock");

    // Save: same rule.
    v.set_prune_clock_offset_for_tests(Duration::ZERO);
    fs::write(&stale, b"half a vault").unwrap();
    insert(&mut v, "x");
    v.save().unwrap();
    assert!(stale.exists(), "younger than 1 h must stay");
    assert!(lock_file.exists(), "save takes the package lock");
    v.set_prune_clock_offset_for_tests(two_hours);
    insert(&mut v, "y");
    v.save().unwrap();
    assert!(!stale.exists());
    assert!(lock_file.exists(), "the lock file is never pruned");
}

/// A directory named `.lock` on a writable volume is not "no locking available": the save
/// fails instead of running unlocked, and nothing is written.
#[test]
fn lock_path_occupied_by_a_directory_fails_the_save() {
    let (_dir, package, mut v) = create();
    fs::create_dir(package.join(".lock")).unwrap();
    let before = fs::read(package.join(VAULT_FILE_NAME)).unwrap();
    insert(&mut v, "x");
    let err = v.save().unwrap_err();
    assert!(matches!(err, vault_sync::SyncError::Io { .. }), "{err:?}");
    assert!(v.is_dirty());
    assert_eq!(fs::read(package.join(VAULT_FILE_NAME)).unwrap(), before);
}

/// Records, for every `ensure_downloaded` of `vault.bin`, whether the package lock was held.
#[derive(Default)]
struct LockProbe {
    calls: std::sync::Mutex<Vec<bool>>,
}

impl CloudHooks for LockProbe {
    fn is_evicted(&self, _path: &Path) -> bool {
        false
    }

    fn ensure_downloaded(&self, path: &Path, _timeout: Duration) -> Result<(), CloudError> {
        if path.file_name() == Some(VAULT_FILE_NAME.as_ref()) {
            let lock = path.parent().unwrap().join(".lock");
            let held = match fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock)
            {
                // A fresh descriptor conflicts with the save's lock even in this process.
                Ok(f) => f.try_lock().is_err(),
                Err(_) => false,
            };
            self.calls.lock().unwrap().push(held);
        }
        Ok(())
    }

    fn pin(&self, _path: &Path) {}
}

/// `ensure_downloaded` may block for 30 s, longer than another writer waits for the lock
/// (10 s): a dirty save must download before it locks.
#[test]
fn save_downloads_the_primary_before_taking_the_lock() {
    let (_dir, package, v) = create();
    drop(v);
    let probe = Arc::new(LockProbe::default());
    let mut v = SyncedVault::open(&package, DEV_A, probe.clone()).unwrap();
    v.unlock(&pw()).unwrap();
    probe.calls.lock().unwrap().clear();
    insert(&mut v, "x");
    v.save().unwrap();
    let calls = probe.calls.lock().unwrap().clone();
    assert_eq!(
        calls.first(),
        Some(&false),
        "first download must be unlocked: {calls:?}"
    );
}
