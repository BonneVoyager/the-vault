//! Refusing to overwrite what must not be overwritten, and never losing in-memory state:
//! save blocks (newer format, foreign vault), key mismatch on lock, tampered files that look
//! like a key mismatch, tampered changes while locked, and reconciling on save/unlock without a
//! watcher.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::format::VaultFile;
use vault_core::{Item, KdfParams, LockedVault, SecretString, SecretVec, UnlockedVault, Uuid};
use vault_sync::{
    BackupKind, CloudError, CloudHooks, NoopHooks, SaveBlocked, SyncError, SyncEvent, SyncedVault,
    VAULT_FILE_NAME,
};

const T0: u64 = 1_700_000_000_000;
const DEV_A: Uuid = Uuid::from_u128(0xA);
const DEV_B: Uuid = Uuid::from_u128(0xB);

/// Wall-clock milliseconds, for core calls that stamp the header (`now`), so the stamp is
/// newer than the one `create` set.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

/// A creates the vault with one item and saves; B opens and unlocks the same package. No
/// watchers. The returned path is the package's `vault.bin` (see [`pkg`]).
fn two_devices() -> (TempDir, PathBuf, SyncedVault, SyncedVault) {
    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join("test.vault");
    let mut a = SyncedVault::create(
        &package,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        Arc::new(NoopHooks),
    )
    .unwrap();
    insert(&mut a, "mail");
    a.save().unwrap();
    let mut b = SyncedVault::open(&package, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    (dir, package.join(VAULT_FILE_NAME), a, b)
}

/// The package directory holding the vault file `file`.
fn pkg(file: &Path) -> &Path {
    file.parent().unwrap()
}

fn insert(v: &mut SyncedVault, title: &str) {
    v.edit(|vault| vault.insert(Item::new(title, Uuid::nil(), T0), T0))
        .unwrap();
}

fn titles_of(v: &UnlockedVault) -> Vec<String> {
    let mut t: Vec<String> = v.items().map(|i| i.title.clone()).collect();
    t.sort();
    t
}

fn titles(v: &SyncedVault) -> Vec<String> {
    titles_of(v.vault().unwrap())
}

fn disk_titles(path: &Path) -> Vec<String> {
    titles_of(
        &LockedVault::parse(&fs::read(path).unwrap())
            .unwrap()
            .unlock(&pw())
            .unwrap(),
    )
}

/// Replace `dst` atomically (tmp + rename), as a sync client would.
fn plant(dst: &Path, bytes: &[u8]) {
    let tmp = dst.with_file_name(".planting.tmp");
    fs::write(&tmp, bytes).unwrap();
    fs::rename(&tmp, dst).unwrap();
}

/// `bytes` with the format version in the prefix raised beyond what this build reads.
fn newer_version(bytes: &[u8]) -> Vec<u8> {
    let mut b = bytes.to_vec();
    b[4..6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    b
}

/// `bytes` with one bit of the first item record's ciphertext flipped: parses, same vault id,
/// fails its first AEAD tag (which `unlock_with_key` reports as `WrongPassword`).
fn tamper_first_item(bytes: &[u8]) -> Vec<u8> {
    let mut f = VaultFile::parse(bytes).unwrap();
    f.items[0].ct[0] ^= 0x01;
    f.to_bytes()
}

fn foreign_vault_bytes() -> Vec<u8> {
    UnlockedVault::create(&pw(), KdfParams::for_tests(), DEV_B).serialize()
}

fn events(rx: &Receiver<SyncEvent>) -> Vec<SyncEvent> {
    rx.try_iter().collect()
}

#[test]
fn newer_format_on_disk_blocks_save_until_a_valid_file_returns() {
    let (_dir, path, mut a, _b) = two_devices();
    let valid = fs::read(&path).unwrap();
    let newer = newer_version(&valid);
    plant(&path, &newer);

    insert(&mut a, "from a");
    let rx = a.subscribe();
    assert!(matches!(
        a.save(),
        Err(SyncError::SaveBlocked(SaveBlocked::NewerVersion(0xFFFF)))
    ));
    assert_eq!(
        fs::read(&path).unwrap(),
        newer,
        "newer file was overwritten"
    );
    // Reported as the 03 §3 event, once, and not as a generic error.
    let blocked = SyncEvent::SaveBlocked(SaveBlocked::NewerVersion(0xFFFF));
    let seen = events(&rx);
    assert_eq!(
        seen.iter().filter(|e| **e == blocked).count(),
        1,
        "{seen:?}"
    );
    assert!(!seen.iter().any(|e| matches!(e, SyncEvent::Error(_))));
    // Still blocked on retry, and each refused save is reported.
    assert!(matches!(a.save(), Err(SyncError::SaveBlocked(_))));
    assert_eq!(events(&rx), [blocked]);

    // A valid file of this vault comes back: the block lifts and the save merges into it.
    plant(&path, &valid);
    a.save().unwrap();
    assert_eq!(disk_titles(&path), ["from a", "mail"]);
}

#[test]
fn foreign_vault_on_disk_blocks_save_and_lock_preserves_edits() {
    let (dir, path, mut a, _b) = two_devices();
    let foreign = foreign_vault_bytes();
    plant(&path, &foreign);

    insert(&mut a, "from a");
    let rx = a.subscribe();
    assert!(matches!(
        a.save(),
        Err(SyncError::SaveBlocked(SaveBlocked::ForeignVault))
    ));
    assert_eq!(fs::read(&path).unwrap(), foreign);
    let blocked = SyncEvent::SaveBlocked(SaveBlocked::ForeignVault);
    let seen = events(&rx);
    assert!(seen.contains(&SyncEvent::ForeignVault));
    assert_eq!(
        seen.iter().filter(|e| **e == blocked).count(),
        1,
        "{seen:?}"
    );
    // A clean retry (no pre-write read) still reports the refusal.
    assert!(matches!(
        a.save(),
        Err(SyncError::SaveBlocked(SaveBlocked::ForeignVault))
    ));
    assert_eq!(events(&rx), [blocked]);

    // Locking cannot save, so the dirty vault is preserved in the backups directory.
    a.lock();
    let unsaved = a
        .backups()
        .unwrap()
        .into_iter()
        .find(|b| b.kind == BackupKind::Unsaved)
        .expect("unsaved snapshot");
    assert!(events(&rx).contains(&SyncEvent::BackupTaken(unsaved.path.clone())));
    assert!(
        unsaved
            .path
            .starts_with(dir.path().join("test.vault").join("backups"))
    );
    let preserved = LockedVault::parse(&fs::read(&unsaved.path).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert_eq!(titles_of(&preserved), ["from a", "mail"]);
    assert_eq!(fs::read(&path).unwrap(), foreign);
}

#[test]
fn newer_format_seen_while_locked_still_blocks_after_unlock() {
    let (_dir, path, mut a, _b) = two_devices();
    a.lock();
    let newer = newer_version(&fs::read(&path).unwrap());
    plant(&path, &newer);

    // Unlock opens the last good copy (the newer file cannot be read).
    a.unlock(&pw()).unwrap();
    assert_eq!(titles(&a), ["mail"]);
    insert(&mut a, "from a");
    assert!(matches!(
        a.save(),
        Err(SyncError::SaveBlocked(SaveBlocked::NewerVersion(_)))
    ));
    assert_eq!(fs::read(&path).unwrap(), newer);
}

#[test]
fn key_mismatch_refuses_clean_save_kek_unlock_and_preserves_on_lock() {
    let (_dir, path, mut a, mut b) = two_devices();
    let mut c = SyncedVault::open(pkg(&path), Uuid::from_u128(0xC), Arc::new(NoopHooks)).unwrap();
    c.unlock(&pw()).unwrap();
    c.start_watching().unwrap();
    let rx_c = c.subscribe();

    b.edit(|v| v.rotate_vault_key(&pw(), wall_ms()))
        .unwrap()
        .unwrap();
    insert(&mut b, "from b");
    b.save().unwrap();
    let rotated = fs::read(&path).unwrap();

    // A (no watcher) notices on save, before writing.
    insert(&mut a, "from a");
    assert!(matches!(a.save(), Err(SyncError::KeyMismatch)));
    assert_eq!(fs::read(&path).unwrap(), rotated);

    // C (watching, clean) is told by the watcher that the key was rotated (not that the
    // password changed); even a clean save is refused.
    let start = Instant::now();
    let mut seen = Vec::new();
    while !seen.contains(&SyncEvent::KeyRotatedOnDisk) && start.elapsed() < Duration::from_secs(20)
    {
        c.poll();
        seen.extend(rx_c.try_iter());
        thread::sleep(Duration::from_millis(25));
    }
    assert!(seen.contains(&SyncEvent::KeyRotatedOnDisk));
    assert!(!seen.contains(&SyncEvent::KeyMismatch));
    assert!(!c.is_dirty());
    assert!(matches!(c.save(), Err(SyncError::KeyMismatch)));
    // Touch ID cannot resolve it.
    assert!(matches!(
        c.unlock_with_kek(Uuid::nil(), &SecretVec::new(vec![0; 32])),
        Err(SyncError::KeyMismatch)
    ));
    // The password does: adopt the rotated vault and merge (no second rotation event).
    c.unlock(&pw()).unwrap();
    let after: Vec<SyncEvent> = rx_c.try_iter().collect();
    assert!(
        matches!(after.as_slice(), [SyncEvent::Merged(_), ..]),
        "{after:?}"
    );
    assert!(!after.contains(&SyncEvent::KeyRotatedOnDisk));
    c.save().unwrap();
    assert_eq!(titles(&c), ["from b", "mail"]);

    // A locks while the mismatch stands: its unsaved item is preserved, encrypted.
    let rx_a = a.subscribe();
    a.lock();
    let unsaved = a
        .backups()
        .unwrap()
        .into_iter()
        .find(|b| b.kind == BackupKind::Unsaved)
        .expect("unsaved snapshot");
    assert!(events(&rx_a).contains(&SyncEvent::BackupTaken(unsaved.path.clone())));
    let preserved = LockedVault::parse(&fs::read(&unsaved.path).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert_eq!(titles_of(&preserved), ["from a", "mail"]);
    assert_eq!(fs::read(&path).unwrap(), rotated);
}

#[test]
fn tampered_first_record_is_not_adopted_as_a_key_change() {
    let (_dir, path, mut a, _b) = two_devices();
    let tampered = tamper_first_item(&fs::read(&path).unwrap());
    plant(&path, &tampered);

    insert(&mut a, "from a");
    // With the cached key the tampered first record looks like a key mismatch.
    assert!(matches!(a.save(), Err(SyncError::KeyMismatch)));
    assert_eq!(fs::read(&path).unwrap(), tampered);

    // The password unlock reveals tampering: in-memory wins, the flag clears, save rewrites.
    let rx = a.subscribe();
    a.unlock(&pw()).unwrap();
    assert!(events(&rx).contains(&SyncEvent::CorruptOnDisk));
    assert_eq!(titles(&a), ["from a", "mail"]);
    assert!(a.is_dirty());
    a.save().unwrap();
    assert_eq!(disk_titles(&path), ["from a", "mail"]);
    // And a later lock/unlock opens the rewritten file.
    a.lock();
    a.unlock(&pw()).unwrap();
    assert_eq!(titles(&a), ["from a", "mail"]);
}

#[test]
fn tampered_change_while_locked_falls_back_to_last_verified() {
    let (_dir, path, mut a, mut b) = two_devices();
    a.lock();
    insert(&mut b, "from b");
    b.save().unwrap();
    plant(&path, &tamper_first_item(&fs::read(&path).unwrap()));

    let rx = a.subscribe();
    a.unlock(&pw()).unwrap();
    assert!(events(&rx).contains(&SyncEvent::CorruptOnDisk));
    assert_eq!(titles(&a), ["mail"]);
    assert!(a.is_dirty());
    a.save().unwrap();
    assert_eq!(disk_titles(&path), ["mail"]);
}

#[test]
fn save_without_watcher_merges_a_peer_write_first() {
    let (_dir, path, mut a, mut b) = two_devices();
    insert(&mut b, "from b");
    b.save().unwrap();
    insert(&mut a, "from a");
    let rx = a.subscribe();
    a.save().unwrap();
    assert!(
        events(&rx)
            .iter()
            .any(|e| matches!(e, SyncEvent::Merged(_)))
    );
    assert_eq!(disk_titles(&path), ["from a", "from b", "mail"]);
    assert_eq!(titles(&a), ["from a", "from b", "mail"]);
}

#[test]
fn unlock_without_watcher_rereads_disk() {
    let (_dir, _path, mut a, mut b) = two_devices();
    a.lock();
    insert(&mut b, "from b");
    b.save().unwrap();
    a.unlock(&pw()).unwrap();
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!a.is_dirty());
}

fn unsaved_files(v: &SyncedVault) -> Vec<PathBuf> {
    v.backups()
        .unwrap()
        .into_iter()
        .filter(|b| b.kind == BackupKind::Unsaved)
        .map(|b| b.path)
        .collect()
}

fn latest_snapshot(path: &Path) -> PathBuf {
    let v = SyncedVault::open(pkg(path), Uuid::nil(), Arc::new(NoopHooks)).unwrap();
    v.backups()
        .unwrap()
        .into_iter()
        .find(|b| b.kind == BackupKind::Snapshot)
        .unwrap()
        .path
}

#[test]
fn restore_over_unparseable_primary_keeps_its_raw_bytes() {
    let (_dir, path, mut a, _b) = two_devices();
    let snap = latest_snapshot(&path);
    plant(&path, b"half-synced garbage");
    a.restore_from(&snap, &pw()).unwrap();
    let raw = unsaved_files(&a);
    assert_eq!(raw.len(), 1);
    assert_eq!(fs::read(&raw[0]).unwrap(), b"half-synced garbage");
    assert_eq!(fs::read(&path).unwrap(), fs::read(&snap).unwrap());
}

#[test]
fn restore_refuses_to_replace_a_newer_format_primary() {
    let (_dir, path, mut a, _b) = two_devices();
    let snap = latest_snapshot(&path);
    let before = a.backups().unwrap().len();
    let newer = newer_version(&fs::read(&path).unwrap());
    plant(&path, &newer);
    assert!(matches!(
        a.restore_from(&snap, &pw()),
        Err(SyncError::SaveBlocked(SaveBlocked::NewerVersion(0xFFFF)))
    ));
    assert_eq!(fs::read(&path).unwrap(), newer);
    assert_eq!(a.backups().unwrap().len(), before);
}

/// Times out `ensure_downloaded` while `.0` is set.
struct Flaky(AtomicBool);

impl CloudHooks for Flaky {
    fn is_evicted(&self, _path: &Path) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    fn ensure_downloaded(&self, _path: &Path, _timeout: Duration) -> Result<(), CloudError> {
        if self.0.load(Ordering::SeqCst) {
            Err(CloudError::Timeout)
        } else {
            Ok(())
        }
    }
    fn pin(&self, _path: &Path) {}
}

#[test]
fn save_does_not_overwrite_a_primary_it_cannot_download() {
    let (_dir, path, _a, mut b) = two_devices();
    let hooks = Arc::new(Flaky(AtomicBool::new(false)));
    let mut c = SyncedVault::open(pkg(&path), Uuid::from_u128(0xC), hooks.clone()).unwrap();
    c.unlock(&pw()).unwrap();
    insert(&mut b, "from b");
    b.save().unwrap();
    let peer = fs::read(&path).unwrap();

    insert(&mut c, "from c");
    hooks.0.store(true, Ordering::SeqCst);
    let rx = c.subscribe();
    assert!(matches!(
        c.save(),
        Err(SyncError::Cloud(CloudError::Timeout))
    ));
    assert_eq!(
        fs::read(&path).unwrap(),
        peer,
        "unmerged peer version overwritten"
    );
    assert!(events(&rx).contains(&SyncEvent::CloudUnavailable));
    assert!(c.is_dirty());

    hooks.0.store(false, Ordering::SeqCst);
    c.save().unwrap();
    assert_eq!(disk_titles(&path), ["from b", "from c", "mail"]);
}

#[test]
fn repeated_locks_while_blocked_keep_one_unsaved_file_per_change() {
    let (_dir, path, mut a, _b) = two_devices();
    plant(&path, &foreign_vault_bytes());
    insert(&mut a, "from a");
    assert!(matches!(a.save(), Err(SyncError::SaveBlocked(_))));
    a.lock();
    assert_eq!(unsaved_files(&a).len(), 1);
    a.unlock(&pw()).unwrap();
    a.lock();
    assert_eq!(unsaved_files(&a).len(), 1, "unchanged state written again");
    // A real change is preserved in a new file.
    a.unlock(&pw()).unwrap();
    insert(&mut a, "later");
    a.lock();
    assert_eq!(unsaved_files(&a).len(), 2);
}

#[test]
fn future_dated_snapshot_does_not_force_a_snapshot_every_save() {
    let (dir, _path, mut a, _b) = two_devices();
    // The first save already took a fresh snapshot.
    let backups = dir.path().join("test.vault").join("backups");
    fs::write(backups.join("test-2099-01-01T00-00-00Z.vault.bin"), b"x").unwrap();
    let before = a.backups().unwrap().len();
    insert(&mut a, "more");
    a.save().unwrap();
    assert_eq!(a.backups().unwrap().len(), before);
}

#[test]
fn failed_snapshot_for_a_deletion_is_retried() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _path, mut a, _b) = two_devices();
    let backups = dir.path().join("test.vault").join("backups");
    let count = |a: &SyncedVault| a.backups().unwrap().len();
    let before = count(&a);
    let id = a.vault().unwrap().items().next().unwrap().id;
    a.edit(|v| v.delete(id, T0 + 1)).unwrap().unwrap();
    fs::set_permissions(&backups, fs::Permissions::from_mode(0o500)).unwrap();
    a.save().unwrap();
    fs::set_permissions(&backups, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(count(&a), before, "snapshot unexpectedly succeeded");

    // No deletion and a fresh snapshot exist, yet the failed one is retried.
    insert(&mut a, "next");
    a.save().unwrap();
    assert_eq!(count(&a), before + 1);
}

/// Reports every backups-directory file as evicted and counts download requests for them.
#[derive(Default)]
struct EvictedBackups(std::sync::atomic::AtomicUsize);

fn in_backups(path: &Path) -> bool {
    path.parent()
        .and_then(|p| p.file_name())
        .is_some_and(|n| n == "backups")
}

impl CloudHooks for EvictedBackups {
    fn is_evicted(&self, path: &Path) -> bool {
        in_backups(path)
    }
    fn ensure_downloaded(&self, path: &Path, _timeout: Duration) -> Result<(), CloudError> {
        if in_backups(path) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
    fn pin(&self, _path: &Path) {}
}

#[test]
fn lock_does_not_download_an_evicted_unsaved_copy() {
    let (_dir, path, _a, _b) = two_devices();
    let hooks = Arc::new(EvictedBackups::default());
    let mut c = SyncedVault::open(pkg(&path), Uuid::from_u128(0xC), hooks.clone()).unwrap();
    c.unlock(&pw()).unwrap();
    plant(&path, &foreign_vault_bytes());
    insert(&mut c, "from c");
    assert!(matches!(c.save(), Err(SyncError::SaveBlocked(_))));
    c.lock();
    c.unlock(&pw()).unwrap();
    c.lock();
    // The evicted copy was not checked, so a fresh one was written instead of waiting.
    assert_eq!(unsaved_files(&c).len(), 2);
    assert_eq!(hooks.0.load(Ordering::SeqCst), 0);
}
