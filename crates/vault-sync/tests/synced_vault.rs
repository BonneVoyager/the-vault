//! Phase-2 `SyncedVault` behaviour: create, open, unlock, edit, atomic save (03 §2, §7, §8).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use vault_core::{
    Item, ItemKind, KdfParams, LockedVault, SecretString, SlotKind, Uuid, VaultError,
};
use vault_sync::{CloudError, CloudHooks, NoopHooks, SyncError, SyncedVault};

const NOW: u64 = 1_700_000_000_000;

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn device() -> Uuid {
    Uuid::from_u128(0xD0D0)
}

fn hooks() -> Arc<dyn CloudHooks> {
    Arc::new(NoopHooks)
}

fn setup() -> (TempDir, PathBuf, SyncedVault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let v = SyncedVault::create(&path, &pw(), KdfParams::for_tests(), device(), hooks()).unwrap();
    (dir, path, v)
}

fn tmp_leftovers(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect()
}

fn insert_item(v: &mut SyncedVault, title: &str) -> Uuid {
    v.edit(|vault| vault.insert(Item::new(ItemKind::Login, title, Uuid::nil(), NOW), NOW))
        .unwrap()
}

#[test]
fn create_writes_parseable_private_file() {
    let (dir, path, v) = setup();
    let bytes = fs::read(&path).unwrap();
    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(locked.vault_id(), v.vault().unwrap().vault_id());
    assert!(tmp_leftovers(dir.path()).is_empty());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let lw = v.last_written().expect("last_written set");
    assert_eq!(lw.size, bytes.len() as u64);
    assert_eq!(&lw.hash, blake3::hash(&bytes).as_bytes());
    assert_eq!(
        lw.mtime,
        Some(fs::metadata(&path).unwrap().modified().unwrap())
    );

    assert!(!v.is_dirty());
    assert_eq!(v.device_id(), device());
    assert_eq!(v.vault().unwrap().device_id(), device());
    assert_eq!(v.path(), path);
    let summary = v.locked_summary();
    assert_eq!(summary.vault_id, locked.vault_id());
    assert_eq!(summary.slots.len(), 1);
    assert_eq!(summary.slots[0].1, SlotKind::Password);
}

#[test]
fn create_refuses_existing_path() {
    let (_dir, path, _v) = setup();
    let before = fs::read(&path).unwrap();
    let err =
        SyncedVault::create(&path, &pw(), KdfParams::for_tests(), device(), hooks()).unwrap_err();
    assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn edit_save_reopen_round_trip() {
    let (_dir, path, v) = setup();
    drop(v);

    let other = Uuid::from_u128(0xBEEF);
    let mut a = SyncedVault::open(&path, other, hooks()).unwrap();
    assert!(a.vault().is_none());
    a.unlock(&pw()).unwrap();
    assert_eq!(a.vault().unwrap().device_id(), other);
    let id = insert_item(&mut a, "Example");
    assert!(a.is_dirty());
    a.save().unwrap();
    assert!(!a.is_dirty());

    let mut b = SyncedVault::open(&path, device(), hooks()).unwrap();
    b.unlock(&pw()).unwrap();
    let item = b.vault().unwrap().get(id).expect("item persisted");
    assert_eq!(item.title, "Example");
    assert_eq!(item.device_id, other);
}

#[test]
fn locked_operations_fail() {
    let (_dir, path, mut v) = setup();
    v.lock();
    assert!(matches!(v.save(), Err(SyncError::Locked)));
    assert!(matches!(v.edit(|_| ()), Err(SyncError::Locked)));

    let mut opened = SyncedVault::open(&path, device(), hooks()).unwrap();
    assert!(matches!(opened.save(), Err(SyncError::Locked)));
    let wrong = SecretString::new("nope".to_owned());
    let err = opened.unlock(&wrong).unwrap_err();
    assert!(
        matches!(err, SyncError::Vault(VaultError::WrongPassword)),
        "{err:?}"
    );
    assert!(opened.vault().is_none());
}

#[test]
fn open_missing_file_is_no_vault() {
    let dir = tempfile::tempdir().unwrap();
    let err = SyncedVault::open(&dir.path().join("none.vault"), device(), hooks()).unwrap_err();
    assert!(matches!(err, SyncError::NoVault(_)), "{err:?}");
}

/// Restores the directory's permissions even if the test panics.
struct RestorePerms<'a>(&'a Path);

impl Drop for RestorePerms<'_> {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o700));
    }
}

#[test]
fn failed_save_leaves_original_intact() {
    let (dir, path, mut v) = setup();
    let before = fs::read(&path).unwrap();
    let lw_before = v.last_written();
    insert_item(&mut v, "Lost?");

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let guard = RestorePerms(dir.path());
    let err = v.save().unwrap_err();
    drop(guard);

    assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
    assert!(tmp_leftovers(dir.path()).is_empty());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(v.is_dirty(), "edit is still pending after a failed save");
    assert_eq!(v.last_written(), lw_before);

    // Once the directory is writable again, the pending edit saves normally.
    v.save().unwrap();
    assert!(!v.is_dirty());
    assert_ne!(fs::read(&path).unwrap(), before);
}

#[test]
fn lock_then_unlock_again() {
    let (_dir, _path, mut v) = setup();
    let id = insert_item(&mut v, "Saved");
    v.save().unwrap();
    insert_item(&mut v, "Unsaved");

    v.lock();
    assert!(v.vault().is_none());
    assert!(!v.is_dirty());

    v.unlock(&pw()).unwrap();
    let vault = v.vault().unwrap();
    assert!(vault.get(id).is_some());
    assert_eq!(
        vault.items().count(),
        1,
        "unsaved edit was discarded by lock"
    );
    assert_eq!(vault.device_id(), device());
}

#[test]
fn unlock_while_unlocked_keeps_edits_but_checks_password() {
    let (_dir, _path, mut v) = setup();
    let id = insert_item(&mut v, "Pending");
    v.unlock(&pw()).unwrap();
    assert!(v.is_dirty());
    assert!(v.vault().unwrap().get(id).is_some());
    let wrong = SecretString::new("nope".to_owned());
    assert!(matches!(
        v.unlock(&wrong),
        Err(SyncError::Vault(VaultError::WrongPassword))
    ));
}

#[test]
fn save_when_clean_does_not_rewrite() {
    let (_dir, path, mut v) = setup();
    let before = fs::read(&path).unwrap();
    v.save().unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
}

struct TimeoutHooks;

impl CloudHooks for TimeoutHooks {
    fn is_evicted(&self, _path: &Path) -> bool {
        true
    }
    fn ensure_downloaded(&self, _path: &Path, timeout: Duration) -> Result<(), CloudError> {
        assert_eq!(timeout, vault_sync::DOWNLOAD_TIMEOUT);
        Err(CloudError::Timeout)
    }
    fn pin(&self, _path: &Path) {}
}

#[test]
fn download_timeout_fails_open() {
    let (_dir, path, _v) = setup();
    let err = SyncedVault::open(&path, device(), Arc::new(TimeoutHooks)).unwrap_err();
    assert!(
        matches!(err, SyncError::Cloud(CloudError::Timeout)),
        "{err:?}"
    );
}
