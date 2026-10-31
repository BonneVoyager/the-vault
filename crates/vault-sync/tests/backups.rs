//! Snapshots, retention wiring and restore through `SyncedVault` (03 §4, §8, §9).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::{Item, KdfParams, SecretString, Uuid};
use vault_sync::{
    CloudError, CloudHooks, NoopHooks, SyncError, SyncEvent, SyncedVault, VAULT_FILE_NAME,
};

const NOW: u64 = 1_700_000_000_000;

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn setup() -> (TempDir, PathBuf, SyncedVault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let v = SyncedVault::create(
        &path,
        &pw(),
        KdfParams::for_tests(),
        Uuid::from_u128(0xD0D0),
        Arc::new(NoopHooks),
    )
    .unwrap();
    (dir, path, v)
}

fn insert_item(v: &mut SyncedVault, title: &str) -> Uuid {
    v.edit(|vault| vault.insert(Item::new(title, Uuid::nil(), NOW), NOW))
        .unwrap()
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

fn backups_taken(rx: &Receiver<SyncEvent>) -> Vec<PathBuf> {
    rx.try_iter()
        .filter_map(|e| match e {
            SyncEvent::BackupTaken(p) => Some(p),
            _ => None,
        })
        .collect()
}

/// `<package>/backups` for the `test.vault` package in `dir`.
fn backups_dir(dir: &Path) -> PathBuf {
    dir.join("test.vault").join("backups")
}

/// `<package>/vault.bin`.
fn bin(package: &Path) -> PathBuf {
    package.join(VAULT_FILE_NAME)
}

#[test]
fn two_saves_in_a_second_take_one_snapshot() {
    let (dir, path, mut v) = setup();
    let rx = v.subscribe();
    insert_item(&mut v, "a");
    v.save().unwrap();
    insert_item(&mut v, "b");
    v.save().unwrap();

    let taken = backups_taken(&rx);
    assert_eq!(taken.len(), 1);
    let list = v.backups().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].path, taken[0]);
    // The snapshot is the first save's bytes, not the second's.
    assert_ne!(fs::read(&taken[0]).unwrap(), fs::read(bin(&path)).unwrap());
    assert_eq!(list[0].size, fs::metadata(&taken[0]).unwrap().len());

    let name = taken[0].file_name().unwrap().to_str().unwrap().to_owned();
    assert!(
        name.starts_with("test-") && name.ends_with("Z.vault.bin"),
        "{name}"
    );
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&backups_dir(dir.path())), 0o700);
    assert_eq!(mode(&taken[0]), 0o600);
    // No tmp files left in the backups directory.
    assert_eq!(fs::read_dir(backups_dir(dir.path())).unwrap().count(), 1);
}

#[test]
fn deleting_an_item_takes_an_extra_snapshot() {
    let (_dir, path, mut v) = setup();
    let rx = v.subscribe();
    let a = insert_item(&mut v, "a");
    insert_item(&mut v, "b");
    v.save().unwrap();
    v.edit(|vault| vault.delete(a, NOW + 1)).unwrap().unwrap();
    v.save().unwrap();

    let taken = backups_taken(&rx);
    assert_eq!(taken.len(), 2);
    // Same second as the first: the second gets a `-2` suffix and lists as newest.
    let list = v.backups().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].path, taken[1]);
    assert_eq!(fs::read(&taken[1]).unwrap(), fs::read(bin(&path)).unwrap());

    // An edit that does not reduce the count does not trigger another one.
    insert_item(&mut v, "c");
    v.save().unwrap();
    assert!(backups_taken(&rx).is_empty());
}

#[test]
fn first_save_after_unlock_snapshots() {
    let (_dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    assert_eq!(v.backups().unwrap().len(), 1);
    let _ = v.lock();
    v.unlock(&pw()).unwrap();
    insert_item(&mut v, "b");
    v.save().unwrap();
    assert_eq!(v.backups().unwrap().len(), 2);
}

#[test]
fn backup_now_copies_primary_even_while_locked() {
    let (_dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let _ = v.lock();
    let rx = v.subscribe();
    let snap = v.backup_now().unwrap();
    assert_eq!(fs::read(&snap).unwrap(), fs::read(bin(&path)).unwrap());
    assert_eq!(backups_taken(&rx), vec![snap.clone()]);
    assert_eq!(v.backups().unwrap()[0].path, snap);
}

#[test]
fn backup_now_ignores_disabled_setting_and_policy() {
    let (_dir, _path, mut v) = setup();
    v.set_backup_enabled(false);
    v.backup_now().unwrap();
    v.backup_now().unwrap();
    assert_eq!(v.backups().unwrap().len(), 2);
}

#[test]
fn disabled_backups_skip_save_snapshots() {
    let (dir, _path, mut v) = setup();
    v.set_backup_enabled(false);
    let rx = v.subscribe();
    let a = insert_item(&mut v, "a");
    v.save().unwrap();
    v.edit(|vault| vault.delete(a, NOW + 1)).unwrap().unwrap();
    v.save().unwrap();
    assert!(backups_taken(&rx).is_empty());
    assert!(v.backups().unwrap().is_empty());
    assert!(!backups_dir(dir.path()).exists());
}

#[test]
fn restore_replaces_primary_and_snapshots_old_state() {
    let (_dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    let snap_bytes = fs::read(&snap).unwrap();

    insert_item(&mut v, "b");
    v.save().unwrap();
    let before = fs::read(bin(&path)).unwrap();
    insert_item(&mut v, "unsaved");
    let rx = v.subscribe();

    v.restore_from(&snap, &pw()).unwrap();

    assert_eq!(fs::read(bin(&path)).unwrap(), snap_bytes);
    assert_eq!(titles(&v), ["a"]);
    assert!(!v.is_dirty());
    assert_eq!(v.vault().unwrap().device_id(), Uuid::from_u128(0xD0D0));
    // Pre-restore snapshot of the on-disk state (a, b; not the unsaved edit).
    let taken = backups_taken(&rx);
    assert_eq!(taken.len(), 1);
    assert_eq!(fs::read(&taken[0]).unwrap(), before);
    assert_eq!(v.backups().unwrap().len(), 2);

    // `last_written` tracks the restored bytes, and the state survives lock/unlock.
    let reopened = SyncedVault::open(&path, Uuid::nil(), Arc::new(NoopHooks)).unwrap();
    assert_eq!(
        v.last_written().unwrap().hash,
        reopened.last_written().unwrap().hash
    );
    let _ = v.lock();
    v.unlock(&pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);
}

#[test]
fn restore_with_wrong_password_changes_nothing() {
    let (_dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    insert_item(&mut v, "b");
    v.save().unwrap();
    insert_item(&mut v, "unsaved");
    let before = fs::read(bin(&path)).unwrap();
    let rx = v.subscribe();

    let err = v
        .restore_from(&snap, &SecretString::new("wrong".to_owned()))
        .unwrap_err();
    assert!(matches!(err, SyncError::Vault(_)), "{err:?}");
    assert_eq!(fs::read(bin(&path)).unwrap(), before);
    assert_eq!(titles(&v), ["a", "b", "unsaved"]);
    assert!(v.is_dirty());
    assert!(backups_taken(&rx).is_empty());
    assert_eq!(v.backups().unwrap().len(), 1);
}

#[test]
fn restore_rejects_a_different_vault() {
    let (_dir, path, mut v) = setup();
    let (_dir2, other_path, _other) = setup();
    let before = fs::read(bin(&path)).unwrap();
    let err = v.restore_from(&other_path, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::ForeignVault { .. }), "{err:?}");
    assert_eq!(fs::read(bin(&path)).unwrap(), before);
    assert!(v.backups().unwrap().is_empty());
}

#[test]
fn restore_works_from_locked_and_over_a_corrupt_primary() {
    let (_dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    let _ = v.lock();
    fs::write(bin(&path), b"garbage").unwrap();

    v.restore_from(&snap, &pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);
    assert_eq!(fs::read(bin(&path)).unwrap(), fs::read(&snap).unwrap());
    // The unparseable primary is kept raw (as an unsaved, never-pruned file).
    let list = v.backups().unwrap();
    assert_eq!(list.len(), 2);
    let raw = list
        .iter()
        .find(|b| b.kind == vault_sync::BackupKind::Unsaved)
        .unwrap();
    assert_eq!(fs::read(&raw.path).unwrap(), b"garbage");
}

#[test]
fn conflict_files_are_listed_and_unknown_files_ignored() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let b = backups_dir(dir.path());
    // An absorbed conflict is a whole package directory.
    let conflict = b.join("conflict-2026-10-28T14-03-11Z-test (Mac's conflicted copy).vault");
    fs::create_dir(&conflict).unwrap();
    fs::write(bin(&conflict), b"x").unwrap();
    fs::write(b.join("notes.txt"), b"x").unwrap();
    // Directories that are not conflict packages are ignored, even with a snapshot-like name.
    fs::create_dir(b.join("test-2026-10-28T14-03-11Z.vault.bin")).unwrap();

    let list = v.backups().unwrap();
    assert_eq!(list.len(), 2);
    let c = list.iter().find(|i| i.path == conflict).unwrap();
    assert_eq!(c.size, 1);
    assert_eq!(
        c.taken_at,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_793_196_191)
    );
}

#[test]
fn retention_runs_after_a_snapshot() {
    let (dir, _path, mut v) = setup();
    let b = backups_dir(dir.path());
    fs::create_dir(&b).unwrap();
    // Two old snapshots in the same month beyond the weekly window: only the newer survives.
    let old_a = b.join("test-2020-01-05T00-00-00Z.vault.bin");
    let old_b = b.join("test-2020-01-20T00-00-00Z.vault.bin");
    let stray = b.join("notes.txt");
    for p in [&old_a, &old_b, &stray] {
        fs::write(p, b"x").unwrap();
    }
    insert_item(&mut v, "a");
    v.save().unwrap();
    assert!(!old_a.exists());
    assert!(old_b.exists());
    assert!(stray.exists());
    assert_eq!(v.backups().unwrap().len(), 2);
}

#[test]
fn retention_multiplier_is_clamped() {
    let (_dir, _path, mut v) = setup();
    assert_eq!(v.retention_multiplier(), 1.0);
    v.set_retention_multiplier(10.0);
    assert_eq!(v.retention_multiplier(), 4.0);
    v.set_retention_multiplier(0.0);
    assert_eq!(v.retention_multiplier(), 0.5);
}

/// Times out `ensure_downloaded` for one chosen path (an evicted file that never arrives).
#[derive(Default)]
struct EvictedPath(Mutex<Option<PathBuf>>);

impl CloudHooks for EvictedPath {
    fn is_evicted(&self, path: &Path) -> bool {
        self.0.lock().unwrap().as_deref() == Some(path)
    }
    fn ensure_downloaded(&self, path: &Path, _timeout: Duration) -> Result<(), CloudError> {
        if self.is_evicted(path) {
            Err(CloudError::Timeout)
        } else {
            Ok(())
        }
    }
    fn pin(&self, _path: &Path) {}
}

#[test]
fn backup_and_restore_wait_for_cloud_download() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let hooks = Arc::new(EvictedPath::default());
    let mut v = SyncedVault::create(
        &path,
        &pw(),
        KdfParams::for_tests(),
        Uuid::from_u128(0xD0D0),
        hooks.clone(),
    )
    .unwrap();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    insert_item(&mut v, "b");
    v.save().unwrap();
    let before = fs::read(bin(&path)).unwrap();
    let is_timeout = |e: SyncError| matches!(e, SyncError::Cloud(CloudError::Timeout));

    // Primary evicted: backup_now and restore_from both fail before touching anything.
    *hooks.0.lock().unwrap() = Some(bin(&path));
    assert!(is_timeout(v.backup_now().unwrap_err()));
    assert!(is_timeout(v.restore_from(&snap, &pw()).unwrap_err()));
    // Backup evicted: restore_from fails too.
    *hooks.0.lock().unwrap() = Some(snap.clone());
    assert!(is_timeout(v.restore_from(&snap, &pw()).unwrap_err()));

    assert_eq!(fs::read(bin(&path)).unwrap(), before);
    assert_eq!(titles(&v), ["a", "b"]);
    assert_eq!(v.backups().unwrap().len(), 1);
}

#[test]
fn fresh_conflict_file_does_not_suppress_hourly_snapshot() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    // Turn our seconds-old snapshot into a just-absorbed conflict package, leaving no snapshot
    // of our own (as if the last one were over an hour old and pruned).
    let ours = v.backups().unwrap()[0].path.clone();
    let name = ours.file_name().unwrap().to_str().unwrap();
    let stamp = &name["test-".len()..name.len() - ".vault.bin".len()];
    let conflict =
        backups_dir(dir.path()).join(format!("conflict-{stamp}-test (conflicted copy).vault"));
    fs::create_dir(&conflict).unwrap();
    fs::rename(&ours, bin(&conflict)).unwrap();
    assert!(v.backups().unwrap()[0].is_conflict());

    let rx = v.subscribe();
    insert_item(&mut v, "b");
    v.save().unwrap();
    assert_eq!(backups_taken(&rx).len(), 1);
    assert!(conflict.exists());
}

#[test]
fn failed_first_snapshot_is_retried_on_next_save() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    // A fresh snapshot exists, so only the first-save-after-unlock flag can trigger the next.
    let _ = v.lock();
    v.unlock(&pw()).unwrap();
    let b = backups_dir(dir.path());
    let set_mode = |m| fs::set_permissions(&b, fs::Permissions::from_mode(m)).unwrap();
    set_mode(0o500);
    let rx = v.subscribe();
    insert_item(&mut v, "b");
    v.save().unwrap();
    set_mode(0o700);
    assert!(
        rx.try_iter().any(|e| matches!(e, SyncEvent::Error(_))),
        "snapshot failure is reported"
    );
    assert_eq!(v.backups().unwrap().len(), 1);

    insert_item(&mut v, "c");
    v.save().unwrap();
    assert_eq!(backups_taken(&rx).len(), 1);
    assert_eq!(v.backups().unwrap().len(), 2);

    // Consumed once it succeeds.
    insert_item(&mut v, "d");
    v.save().unwrap();
    assert!(backups_taken(&rx).is_empty());
}

#[test]
fn restore_from_an_absorbed_conflict_package() {
    let (dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    let conflict = backups_dir(dir.path()).join("conflict-2026-10-28T14-03-11Z-test 2.vault");
    fs::create_dir(&conflict).unwrap();
    fs::copy(&snap, bin(&conflict)).unwrap();
    insert_item(&mut v, "b");
    v.save().unwrap();

    let listed = v.backups().unwrap();
    let c = listed.iter().find(|b| b.is_conflict()).unwrap();
    assert_eq!(c.path, conflict);
    assert_eq!(c.size, fs::metadata(&snap).unwrap().len());

    v.restore_from(&conflict, &pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);
    assert_eq!(fs::read(bin(&path)).unwrap(), fs::read(&snap).unwrap());
    // The package itself is left in the backups directory.
    assert!(bin(&conflict).exists());
}

fn deleted(rx: &Receiver<SyncEvent>) -> Vec<PathBuf> {
    rx.try_iter()
        .filter_map(|e| match e {
            SyncEvent::BackupDeleted(p) => Some(p),
            _ => None,
        })
        .collect()
}

#[test]
fn delete_backup_removes_a_snapshot() {
    let (_dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    assert!(snap.is_file());
    let rx = v.subscribe();

    v.delete_backup(&snap).unwrap();
    assert!(!snap.exists());
    assert!(v.backups().unwrap().iter().all(|b| b.path != snap));
    assert_eq!(deleted(&rx), std::slice::from_ref(&snap));
    // Gone now: a second delete is refused, not an I/O error.
    assert!(matches!(
        v.delete_backup(&snap),
        Err(SyncError::NotABackup(_))
    ));
}

#[test]
fn delete_backup_removes_unsaved_and_conflict_packages_while_locked() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    let conflict = backups_dir(dir.path()).join("conflict-2026-10-28T14-03-11Z-test 2.vault");
    fs::create_dir(&conflict).unwrap();
    fs::copy(&snap, bin(&conflict)).unwrap();
    fs::create_dir(conflict.join("attachments")).unwrap();
    fs::write(conflict.join("attachments").join("x.bin"), b"blob").unwrap();
    // A symlink inside the package is removed, never followed.
    let outside = dir.path().join("keep.txt");
    fs::write(&outside, b"keep").unwrap();
    std::os::unix::fs::symlink(&outside, conflict.join("link")).unwrap();
    insert_item(&mut v, "unsaved");
    let _ = v.lock();
    let unsaved = v
        .backups()
        .unwrap()
        .into_iter()
        .find(|b| b.kind == vault_sync::BackupKind::Unsaved)
        .unwrap()
        .path;
    let rx = v.subscribe();

    v.delete_backup(&conflict).unwrap();
    v.delete_backup(&unsaved).unwrap();
    assert!(!conflict.exists());
    assert!(!unsaved.exists());
    assert_eq!(fs::read(&outside).unwrap(), b"keep");
    assert_eq!(deleted(&rx), [conflict, unsaved]);
    let left = v.backups().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].path, snap);
}

#[test]
fn delete_backup_refuses_anything_that_is_not_a_backup() {
    let (dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    let b = backups_dir(dir.path());
    let rx = v.subscribe();
    let refused = |v: &mut SyncedVault, p: &Path| {
        assert!(
            matches!(v.delete_backup(p), Err(SyncError::NotABackup(_))),
            "{} was not refused",
            p.display()
        );
    };

    // The primary, the package, the backups directory itself and the lock file.
    refused(&mut v, &bin(&path));
    refused(&mut v, &path);
    refused(&mut v, &b);
    refused(&mut v, &path.join(".lock"));
    // A file outside the package, and a symlink in backups/ pointing at it or at the primary.
    let outside = dir.path().join("test-2026-10-28T14-03-11Z.vault.bin");
    fs::copy(&snap, &outside).unwrap();
    refused(&mut v, &outside);
    let link = b.join("test-2026-10-27T14-03-11Z.vault.bin");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    refused(&mut v, &link);
    let link_primary = b.join("test-2026-10-26T14-03-11Z.vault.bin");
    std::os::unix::fs::symlink(bin(&path), &link_primary).unwrap();
    refused(&mut v, &link_primary);
    // `..` escapes are resolved before the check.
    refused(&mut v, &b.join("..").join(VAULT_FILE_NAME));
    // A file in backups/ without a backup name, and a file inside a conflict package.
    let stray = b.join("notes.txt");
    fs::write(&stray, b"x").unwrap();
    refused(&mut v, &stray);
    let conflict = b.join("conflict-2026-10-28T14-03-11Z-test 2.vault");
    fs::create_dir(&conflict).unwrap();
    fs::copy(&snap, bin(&conflict)).unwrap();
    refused(&mut v, &bin(&conflict));
    // A missing path.
    refused(&mut v, &b.join("test-2020-01-01T00-00-00Z.vault.bin"));

    assert!(outside.exists() && stray.exists() && bin(&conflict).exists());
    assert!(bin(&path).exists() && snap.exists());
    assert!(deleted(&rx).is_empty());
    let _ = v.lock();
    v.unlock(&pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);
}

/// A symlink in backups/ named like a backup and pointing at another listed backup is refused
/// (never followed), and both files survive.
#[test]
fn delete_backup_refuses_a_symlink_to_another_backup() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    let link = backups_dir(dir.path()).join("test-2026-10-27T14-03-11Z.vault.bin");
    std::os::unix::fs::symlink(&snap, &link).unwrap();
    let rx = v.subscribe();

    assert!(matches!(
        v.delete_backup(&link),
        Err(SyncError::NotABackup(_))
    ));
    assert!(snap.is_file());
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(deleted(&rx).is_empty());
    // A path through a symlinked directory to the real backups/ is still accepted.
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(backups_dir(dir.path()), &alias).unwrap();
    v.delete_backup(&alias.join(snap.file_name().unwrap()))
        .unwrap();
    assert!(!snap.exists());
    assert_eq!(deleted(&rx), std::slice::from_ref(&snap));
}
