//! Phase-2 `SyncedVault` behaviour: create, open, unlock, edit, atomic save (03 §1, §2, §7, §8).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use vault_core::{Item, KdfParams, LockedVault, SecretString, SlotKind, Uuid, VaultError};
use vault_sync::{CloudError, CloudHooks, NoopHooks, SyncError, SyncedVault, VAULT_FILE_NAME};

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

/// `<package>/vault.bin`.
fn bin(package: &Path) -> PathBuf {
    package.join(VAULT_FILE_NAME)
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Returns the package path.
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
    v.edit(|vault| vault.insert(new_item(title), NOW)).unwrap()
}

fn new_item(title: &str) -> Item {
    Item::new(title, Uuid::nil(), NOW)
}

#[test]
fn create_writes_parseable_private_file() {
    let (dir, path, v) = setup();
    let bytes = fs::read(bin(&path)).unwrap();
    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(locked.vault_id(), v.vault().unwrap().vault_id());
    assert!(tmp_leftovers(dir.path()).is_empty());
    assert!(tmp_leftovers(&path).is_empty());

    let lw = v.last_written().expect("last_written set");
    assert_eq!(lw.size, bytes.len() as u64);
    assert_eq!(&lw.hash, blake3::hash(&bytes).as_bytes());
    assert_eq!(
        lw.mtime,
        Some(fs::metadata(bin(&path)).unwrap().modified().unwrap())
    );

    assert!(!v.is_dirty());
    assert_eq!(v.device_id(), device());
    assert_eq!(v.vault().unwrap().device_id(), device());
    assert_eq!(v.path(), path);
    assert_eq!(v.vault_file(), bin(&path));
    let summary = v.locked_summary();
    assert_eq!(summary.vault_id, locked.vault_id());
    assert_eq!(summary.slots.len(), 1);
    assert_eq!(summary.slots[0].1, SlotKind::Password);
}

#[test]
fn create_produces_a_private_package() {
    let (dir, path, _v) = setup();
    assert!(path.is_dir());
    assert_eq!(mode(&path), 0o700);
    assert_eq!(mode(&bin(&path)), 0o600);
    // Nothing but the vault file: no sibling directories, nothing else inside yet.
    let names = |d: &Path| -> Vec<String> {
        let mut n: Vec<String> = fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    };
    assert_eq!(names(dir.path()), ["test.vault"]);
    assert_eq!(names(&path), [VAULT_FILE_NAME]);
}

#[test]
fn create_refuses_existing_path() {
    let (dir, path, _v) = setup();
    let before = fs::read(bin(&path)).unwrap();
    let err =
        SyncedVault::create(&path, &pw(), KdfParams::for_tests(), device(), hooks()).unwrap_err();
    assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
    assert_eq!(fs::read(bin(&path)).unwrap(), before);

    // An existing empty directory or a file at the path is refused as well.
    for (name, make_dir) in [("empty.vault", true), ("file.vault", false)] {
        let p = dir.path().join(name);
        if make_dir {
            fs::create_dir(&p).unwrap();
        } else {
            fs::write(&p, b"x").unwrap();
        }
        let err =
            SyncedVault::create(&p, &pw(), KdfParams::for_tests(), device(), hooks()).unwrap_err();
        assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
    }
    assert!(
        fs::read_dir(dir.path().join("empty.vault"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn open_on_a_regular_file_is_not_a_package() {
    let (dir, path, _v) = setup();
    // The old single-file layout: a `.vault` file holding the vault bytes.
    let old = dir.path().join("old.vault");
    fs::copy(bin(&path), &old).unwrap();
    let err = SyncedVault::open(&old, device(), hooks()).unwrap_err();
    assert!(
        matches!(&err, SyncError::NotAPackage(p) if p == &old),
        "{err:?}"
    );
    assert!(err.to_string().contains("not a vault package"), "{err}");
    // The vault file itself is not a package either.
    let err = SyncedVault::open(&bin(&path), device(), hooks()).unwrap_err();
    assert!(matches!(err, SyncError::NotAPackage(_)), "{err:?}");
}

#[test]
fn open_package_without_vault_file_is_no_vault() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("empty.vault");
    fs::create_dir(&pkg).unwrap();
    let err = SyncedVault::open(&pkg, device(), hooks()).unwrap_err();
    assert!(
        matches!(&err, SyncError::NoVault(p) if p == &bin(&pkg)),
        "{err:?}"
    );
}

#[test]
fn two_handles_on_one_package_converge_through_save() {
    let (_dir, path, mut a) = setup();
    let mut b = SyncedVault::open(&path, Uuid::from_u128(0xB), hooks()).unwrap();
    b.unlock(&pw()).unwrap();
    let from_a = insert_item(&mut a, "from a");
    a.save().unwrap();
    let from_b = insert_item(&mut b, "from b");
    // The pre-save merge folds a's write into b before b writes.
    b.save().unwrap();
    assert!(b.vault().unwrap().get(from_a).is_some());
    // a's next save (an edit) merges b's write back in; both now hold both items.
    insert_item(&mut a, "again");
    a.save().unwrap();
    assert!(a.vault().unwrap().get(from_b).is_some());
    let mut c = SyncedVault::open(&path, device(), hooks()).unwrap();
    c.unlock(&pw()).unwrap();
    assert_eq!(c.vault().unwrap().items().count(), 3);
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
    let _ = v.lock();
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
    let (_dir, path, mut v) = setup();
    let before = fs::read(bin(&path)).unwrap();
    let lw_before = v.last_written();
    insert_item(&mut v, "Lost?");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    let guard = RestorePerms(&path);
    let err = v.save().unwrap_err();
    drop(guard);

    assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
    assert!(tmp_leftovers(&path).is_empty());
    assert_eq!(fs::read(bin(&path)).unwrap(), before);
    assert!(v.is_dirty(), "edit is still pending after a failed save");
    assert_eq!(v.last_written(), lw_before);

    // Once the directory is writable again, the pending edit saves normally.
    v.save().unwrap();
    assert!(!v.is_dirty());
    assert_ne!(fs::read(bin(&path)).unwrap(), before);
}

#[test]
fn lock_then_unlock_again() {
    let (_dir, _path, mut v) = setup();
    let id = insert_item(&mut v, "Saved");
    v.save().unwrap();
    insert_item(&mut v, "Unsaved");

    let _ = v.lock();
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
    let before = fs::read(bin(&path)).unwrap();
    v.save().unwrap();
    assert_eq!(fs::read(bin(&path)).unwrap(), before);
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

#[test]
fn vault_file_replaced_by_a_directory_is_a_clean_error() {
    let (_dir, path, mut v) = setup();
    fs::remove_file(bin(&path)).unwrap();
    fs::create_dir(bin(&path)).unwrap();
    let err = SyncedVault::open(&path, device(), hooks()).unwrap_err();
    assert!(
        matches!(&err, SyncError::NoVault(p) if p == &bin(&path)),
        "{err:?}"
    );
    // An open vault refuses to save over it, and leaves it alone.
    insert_item(&mut v, "x");
    let err = v.save().unwrap_err();
    assert!(matches!(err, SyncError::Io { .. }), "{err:?}");
    assert!(bin(&path).is_dir());
    assert!(tmp_leftovers(&path).is_empty());
}

#[test]
fn dangling_symlink_is_no_vault() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("link.vault");
    std::os::unix::fs::symlink(dir.path().join("gone.vault"), &link).unwrap();
    let err = SyncedVault::open(&link, device(), hooks()).unwrap_err();
    assert!(matches!(err, SyncError::NoVault(_)), "{err:?}");
}

#[test]
fn non_ascii_package_name_with_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Ärzte Tresor 2026.vault");
    let mut v =
        SyncedVault::create(&path, &pw(), KdfParams::for_tests(), device(), hooks()).unwrap();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = &v.backups().unwrap()[0];
    let name = snap.path.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("Ärzte Tresor 2026-"), "{name}");
    let mut w = SyncedVault::open(&path, device(), hooks()).unwrap();
    w.unlock(&pw()).unwrap();
    assert_eq!(w.vault().unwrap().items().count(), 1);
}

/// 01 §2: the header and the password slot record the creation time (unix seconds), not 0.
#[test]
fn create_stamps_created_at_in_header_and_slot() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (_dir, path, _v) = setup();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let locked = LockedVault::parse(&fs::read(bin(&path)).unwrap()).unwrap();
    let header = locked.header();
    assert!(
        (before..=after).contains(&header.created_at),
        "{}",
        header.created_at
    );
    let slots: Vec<u64> = header
        .slots
        .iter()
        .map(|s| match s {
            vault_core::Slot::Key(k) => k.created_at,
            vault_core::Slot::Opaque(_) => panic!("unexpected opaque slot"),
        })
        .collect();
    assert_eq!(slots, [header.created_at]);
}
