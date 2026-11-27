//! Snapshots, retention wiring and restore through `SyncedVault` (03 §4, §8, §9).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::{Item, KdfParams, LockedVault, SecretString, Uuid};
use vault_sync::{
    BackupKind, CloudError, CloudHooks, LockOutcome, NoopHooks, SyncError, SyncEvent, SyncedVault,
    VAULT_FILE_NAME,
};

const NOW: u64 = 1_700_000_000_000;

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn setup() -> (TempDir, PathBuf, SyncedVault) {
    setup_named("test")
}

/// A fresh package `<name>.vault` in a new temp dir.
fn setup_named(name: &str) -> (TempDir, PathBuf, SyncedVault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{name}.vault"));
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
    // The unsaved edit went to an Unsaved backup first, then the pre-restore snapshot of the
    // on-disk state (a, b).
    let taken = backups_taken(&rx);
    assert_eq!(taken.len(), 2);
    let kind_of = |p: &Path| {
        v.backups()
            .unwrap()
            .into_iter()
            .find(|b| b.path == p)
            .unwrap()
            .kind
    };
    assert_eq!(kind_of(&taken[0]), BackupKind::Unsaved);
    assert_eq!(kind_of(&taken[1]), BackupKind::Snapshot);
    assert_eq!(fs::read(&taken[1]).unwrap(), before);
    assert_eq!(v.backups().unwrap().len(), 3);

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
    let (dir, path, mut v) = setup();
    let b = backups_dir(dir.path());
    fs::create_dir(&b).unwrap();
    // Two old snapshots in the same month beyond the weekly window: only the newer survives.
    // Retention only touches validated files, so they hold this vault's real bytes.
    let old_a = b.join("test-2020-01-05T00-00-00Z.vault.bin");
    let old_b = b.join("test-2020-01-20T00-00-00Z.vault.bin");
    let stray = b.join("notes.txt");
    let bytes = fs::read(bin(&path)).unwrap();
    for p in [&old_a, &old_b, &stray] {
        fs::write(p, &bytes).unwrap();
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

/// The titles in the backup file at `path`, opened with the test password.
fn titles_in(path: &Path) -> Vec<String> {
    let vault = LockedVault::parse(&fs::read(path).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    let mut t: Vec<String> = vault.items().map(|i| i.title.clone()).collect();
    t.sort();
    t
}

fn kinds(v: &SyncedVault) -> Vec<BackupKind> {
    v.backups().unwrap().into_iter().map(|b| b.kind).collect()
}

/// Bug hunt 2026-11-22 L3: unsaved in-memory edits go to an Unsaved backup before a restore
/// replaces them; the restored vault is the backup's.
#[test]
fn restore_keeps_unsaved_edits_in_an_unsaved_backup() {
    let (_dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    let snap_bytes = fs::read(&snap).unwrap();
    insert_item(&mut v, "unsaved");
    assert!(v.is_dirty());

    v.restore_from(&snap, &pw()).unwrap();

    assert_eq!(titles(&v), ["a"]);
    assert!(!v.is_dirty());
    assert_eq!(fs::read(bin(&path)).unwrap(), snap_bytes);
    let unsaved: Vec<_> = v
        .backups()
        .unwrap()
        .into_iter()
        .filter(|b| b.kind == BackupKind::Unsaved)
        .collect();
    assert_eq!(unsaved.len(), 1);
    assert_eq!(titles_in(&unsaved[0].path), ["a", "unsaved"]);
}

/// An Unsaved backup that already holds the edits is not written again (as for `lock`); a
/// failed restore writes none unless it got as far as keeping the edits.
#[test]
fn restore_reuses_a_covering_unsaved_backup() {
    let (_dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    insert_item(&mut v, "unsaved");
    let unsaved_count = |v: &SyncedVault| {
        kinds(v)
            .iter()
            .filter(|k| **k == BackupKind::Unsaved)
            .count()
    };
    // Wrong password: refused before anything is written.
    let wrong = SecretString::new("wrong".to_owned());
    assert!(v.restore_from(&snap, &wrong).is_err());
    assert_eq!(unsaved_count(&v), 0);

    // A primary from a newer format: refused after the edits were kept.
    let primary = fs::read(bin(&path)).unwrap();
    let mut newer = primary.clone();
    newer[4..6].copy_from_slice(&(vault_core::FORMAT_VERSION + 1).to_be_bytes());
    fs::write(bin(&path), &newer).unwrap();
    let err = v.restore_from(&snap, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::SaveBlocked(_)), "{err:?}");
    assert_eq!(unsaved_count(&v), 1);
    assert!(v.is_dirty());

    // Same edits again: the existing Unsaved copy covers them.
    fs::write(bin(&path), &primary).unwrap();
    let rx = v.subscribe();
    v.restore_from(&snap, &pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);
    assert_eq!(unsaved_count(&v), 1);
    assert_eq!(backups_taken(&rx).len(), 1, "only the pre-restore snapshot");
}

/// When the Unsaved write fails, the restore is refused and nothing changes: not the
/// primary, not memory (still dirty), not the backups.
#[test]
fn restore_refuses_when_unsaved_edits_cannot_be_kept() {
    let (dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    insert_item(&mut v, "unsaved");
    let primary = fs::read(bin(&path)).unwrap();
    let b = backups_dir(dir.path());
    let names = |d: &Path| {
        let mut n: Vec<_> = fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        n.sort();
        n
    };
    let listed = names(&b);
    let rx = v.subscribe();

    // A backups directory that refuses writes (listing and reading still work).
    fs::set_permissions(&b, fs::Permissions::from_mode(0o500)).unwrap();
    let err = v.restore_from(&snap, &pw()).unwrap_err();
    fs::set_permissions(&b, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        err.to_string().contains("-unsaved"),
        "the Unsaved write is what failed: {err}"
    );
    assert_eq!(fs::read(bin(&path)).unwrap(), primary);
    assert_eq!(titles(&v), ["a", "unsaved"]);
    assert!(v.is_dirty());
    assert_eq!(names(&b), listed);
    assert!(backups_taken(&rx).is_empty());

    // A symlinked backups directory (03 §1) is refused too, before anything is written.
    let outside = tempfile::tempdir().unwrap();
    let real = dir.path().join("real-backups");
    fs::rename(&b, &real).unwrap();
    std::os::unix::fs::symlink(outside.path(), &b).unwrap();
    let err = v
        .restore_from(&real.join(snap.file_name().unwrap()), &pw())
        .unwrap_err();
    assert!(matches!(err, SyncError::UnsafePackageDir(_)), "{err:?}");
    assert_eq!(fs::read(bin(&path)).unwrap(), primary);
    assert_eq!(titles(&v), ["a", "unsaved"]);
    assert!(v.is_dirty());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

/// A clean vault writes no Unsaved backup on restore.
#[test]
fn restore_of_a_clean_vault_writes_no_unsaved_backup() {
    let (_dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    insert_item(&mut v, "b");
    v.save().unwrap();
    assert!(!v.is_dirty());

    v.restore_from(&snap, &pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);
    assert!(!kinds(&v).contains(&BackupKind::Unsaved));
}

/// Bug hunt 2026-11-22 L1: a package named `conflict` (every backup name starts with
/// `conflict-`) still lists its own snapshots, takes one per hour (not per save), prunes
/// them, and still lists a real conflict copy as a conflict.
#[test]
fn a_vault_named_conflict_manages_its_snapshots() {
    let (dir, path, mut v) = setup_named("conflict");
    let b = dir.path().join("conflict.vault").join("backups");
    let rx = v.subscribe();
    insert_item(&mut v, "a");
    v.save().unwrap();
    insert_item(&mut v, "b");
    v.save().unwrap();
    insert_item(&mut v, "c");
    v.save().unwrap();
    // The 1 h rule holds: one snapshot from three saves.
    assert_eq!(backups_taken(&rx).len(), 1);
    assert_eq!(kinds(&v), [BackupKind::Snapshot]);

    // An Unsaved copy lists as Unsaved.
    insert_item(&mut v, "d");
    assert!(matches!(v.lock(), LockOutcome::Snapshotted(_)));
    let mut k = kinds(&v);
    k.sort_by_key(|k| format!("{k:?}"));
    assert_eq!(k, [BackupKind::Snapshot, BackupKind::Unsaved]);
    let _ = backups_taken(&rx);

    // Retention: two old snapshots in one month beyond the weekly window, a real conflict
    // copy of this package, and a same-second `-2` snapshot.
    let old_a = b.join("conflict-2020-01-05T00-00-00Z.vault.bin");
    let old_b = b.join("conflict-2020-01-20T00-00-00Z.vault.bin");
    let old_b2 = b.join("conflict-2020-01-20T00-00-00Z-2.vault.bin");
    let bytes = fs::read(bin(&path)).unwrap();
    for p in [&old_a, &old_b, &old_b2] {
        fs::write(p, &bytes).unwrap();
    }
    let conflict = b.join("conflict-2020-01-05T00-00-00Z-conflict.vault");
    fs::create_dir(&conflict).unwrap();
    fs::write(bin(&conflict), b"x").unwrap();
    let listed = v.backups().unwrap();
    let kind = |p: &Path| listed.iter().find(|i| i.path == p).map(|i| i.kind);
    assert_eq!(kind(&old_a), Some(BackupKind::Snapshot));
    assert_eq!(kind(&old_b2), Some(BackupKind::Snapshot));
    assert_eq!(kind(&conflict), Some(BackupKind::Conflict));

    // First save after unlock snapshots and runs retention.
    v.unlock(&pw()).unwrap();
    insert_item(&mut v, "e");
    v.save().unwrap();
    assert_eq!(backups_taken(&rx).len(), 1);
    assert!(!old_a.exists());
    assert!(!old_b.exists(), "older of the same second");
    assert!(old_b2.exists(), "newest of its month");
    assert!(conflict.exists(), "conflict copies are never pruned");
}

// ---- L-04: planted names (security review 2026-11-26, Appendix B F2) ----

/// Bytes of a different vault (valid header, foreign id).
fn foreign_vault_bytes() -> Vec<u8> {
    let (_dir, path, _v) = setup_named("test");
    fs::read(bin(&path)).unwrap()
}

#[test]
fn planted_name_does_not_evict_a_genuine_snapshot() {
    let (dir, path, mut v) = setup();
    let b = backups_dir(dir.path());
    fs::create_dir(&b).unwrap();
    // A genuine snapshot and, later in the same month (which would win the monthly slot), an
    // empty file and another vault's file.
    let genuine = b.join("test-2020-01-05T00-00-00Z.vault.bin");
    fs::write(&genuine, fs::read(bin(&path)).unwrap()).unwrap();
    let empty = b.join("test-2020-01-31T23-59-59Z.vault.bin");
    fs::write(&empty, b"").unwrap();
    let foreign = b.join("test-2020-01-20T00-00-00Z.vault.bin");
    fs::write(&foreign, foreign_vault_bytes()).unwrap();

    insert_item(&mut v, "a");
    v.save().unwrap(); // first save: snapshot + retention
    assert!(
        genuine.exists(),
        "genuine snapshot evicted by a planted name"
    );
    assert!(
        empty.exists() && foreign.exists(),
        "unvalidated files are never deleted"
    );
    let list = v.backups().unwrap();
    let validated = |p: &Path| list.iter().find(|i| i.path == p).unwrap().validated;
    assert!(validated(&genuine));
    assert!(!validated(&empty) && !validated(&foreign));
}

#[test]
fn planted_fresh_name_does_not_suppress_the_hourly_snapshot() {
    let (_dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    // Our seconds-old snapshot is replaced by garbage under the same (fresh) name, as if one
    // were planted each hour: no validated snapshot is newer than an hour.
    let ours = v.backups().unwrap()[0].path.clone();
    fs::write(&ours, b"planted").unwrap();
    let rx = v.subscribe();
    insert_item(&mut v, "b");
    v.save().unwrap();
    assert_eq!(backups_taken(&rx).len(), 1);
    assert!(ours.exists());
}

#[test]
fn planted_newer_name_does_not_list_first() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let genuine = v.backups().unwrap()[0].path.clone();
    let b = backups_dir(dir.path());
    let empty = b.join("test-2099-01-01T00-00-00Z.vault.bin");
    fs::write(&empty, b"").unwrap();
    let foreign = b.join("test-2098-01-01T00-00-00Z.vault.bin");
    fs::write(&foreign, foreign_vault_bytes()).unwrap();
    let list = v.backups().unwrap();
    assert_eq!(list[0].path, genuine);
    assert!(list[0].validated);
    let tail: Vec<_> = list[1..].iter().map(|i| (&i.path, i.validated)).collect();
    assert_eq!(tail, [(&empty, false), (&foreign, false)]);
}

// ---- L-06: bounded directory work on the save path ----

#[test]
fn copied_header_plant_does_not_evict_a_genuine_snapshot() {
    let (dir, path, mut v) = setup();
    let b = backups_dir(dir.path());
    fs::create_dir(&b).unwrap();
    let bytes = fs::read(bin(&path)).unwrap();
    let genuine = b.join("test-2020-01-05T00-00-00Z.vault.bin");
    fs::write(&genuine, &bytes).unwrap();
    // The genuine prefix and header, then garbage: passes the header check only.
    let header_end = 10 + u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
    let mut forged = bytes[..header_end].to_vec();
    forged.extend_from_slice(&[0xA5; 512]);
    let plant = b.join("test-2020-01-31T23-59-59Z.vault.bin");
    fs::write(&plant, &forged).unwrap();

    insert_item(&mut v, "a");
    v.save().unwrap(); // first save: snapshot + retention
    assert!(
        genuine.exists(),
        "genuine snapshot evicted by a forged header"
    );
    assert!(plant.exists());
    // The listing stays header-based: the plant reads as validated (and fails at restore);
    // only deletions need full authentication.
    let list = v.backups().unwrap();
    let validated = |p: &Path| list.iter().find(|i| i.path == p).unwrap().validated;
    assert!(validated(&genuine) && validated(&plant));
    assert!(matches!(
        v.restore_from(&plant, &pw()),
        Err(SyncError::Vault(_))
    ));
}

#[test]
fn locked_retention_deletes_nothing() {
    let (dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let b = backups_dir(dir.path());
    let bytes = fs::read(bin(&path)).unwrap();
    let older = b.join("test-2020-01-05T00-00-00Z.vault.bin");
    let newer = b.join("test-2020-01-20T00-00-00Z.vault.bin");
    for p in [&older, &newer] {
        fs::write(p, &bytes).unwrap();
    }
    let _ = v.lock();
    v.backup_now().unwrap();
    assert!(
        older.exists(),
        "no key, no authenticated holder, no deletion"
    );
    v.unlock(&pw()).unwrap();
    v.backup_now().unwrap();
    assert!(!older.exists());
    assert!(newer.exists());
}

#[test]
fn backup_checks_are_cached_across_saves() {
    let (dir, _path, mut v) = setup();
    let a = insert_item(&mut v, "a");
    insert_item(&mut v, "b");
    v.save().unwrap();
    let b = backups_dir(dir.path());
    // Just under the listing cap, so every name is listed on every pass.
    for n in 2..=9_990 {
        fs::write(
            b.join(format!("test-2020-01-01T00-00-00Z-{n}.vault.bin")),
            b"",
        )
        .unwrap();
    }
    v.backups().unwrap();
    let (reads, _) = v.backup_checks_for_tests();
    assert!(reads >= 9_989);
    // A deletion forces a snapshot and a retention pass.
    v.edit(|vault| vault.delete(a, NOW + 1)).unwrap().unwrap();
    let rx = v.subscribe();
    v.save().unwrap();
    assert_eq!(backups_taken(&rx).len(), 1);
    let (again, _) = v.backup_checks_for_tests();
    assert!(
        again - reads <= 4,
        "{} header reads on the second pass",
        again - reads
    );
}

#[test]
fn save_succeeds_with_more_backup_entries_than_the_listing_cap() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let b = backups_dir(dir.path());
    // 10,001 planted snapshot-shaped names (the cap is 10,000 entries per listing).
    for n in 2..=10_002 {
        fs::write(
            b.join(format!("test-2020-01-01T00-00-00Z-{n}.vault.bin")),
            b"",
        )
        .unwrap();
    }
    let total = fs::read_dir(&b).unwrap().count();
    assert!(total > 10_000);
    insert_item(&mut v, "b");
    v.save().unwrap();
    assert!(v.backups().unwrap().len() <= 10_000, "listing is capped");
    // Nothing planted was deleted; at most a new snapshot was added.
    assert!(fs::read_dir(&b).unwrap().count() >= total);
}

#[test]
fn genuine_snapshots_beyond_the_listing_cap_are_not_deleted() {
    let (dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let b = backups_dir(dir.path());
    let bytes = fs::read(bin(&path)).unwrap();
    // Genuine copies sharing one monthly bucket: a full listing would prune all but one.
    for n in 2..=10_002 {
        fs::write(
            b.join(format!("test-2020-01-01T00-00-00Z-{n}.vault.bin")),
            &bytes,
        )
        .unwrap();
    }
    let total = fs::read_dir(&b).unwrap().count();
    let id = v.vault().unwrap().items().next().unwrap().id;
    v.edit(|vault| vault.delete(id, NOW + 1)).unwrap().unwrap();
    v.save().unwrap(); // deletion: snapshot, then retention over a truncated listing
    assert!(
        fs::read_dir(&b).unwrap().count() > total,
        "nothing deleted, one snapshot added"
    );
}

/// Snapshots sealed under a since-rotated key stay listed as validated (the backup viewer
/// opens them with the password) but are never pruned: they cannot be authenticated under
/// the current key.
#[test]
fn pre_rotation_snapshots_stay_listed_and_are_not_pruned() {
    let (dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let b = backups_dir(dir.path());
    let old_key_bytes = fs::read(bin(&path)).unwrap();
    let older = b.join("test-2020-01-05T00-00-00Z.vault.bin");
    let newer = b.join("test-2020-01-20T00-00-00Z.vault.bin");
    for p in [&older, &newer] {
        fs::write(p, &old_key_bytes).unwrap();
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    v.edit(|vault| vault.rotate_vault_key(&pw(), now_ms))
        .unwrap()
        .unwrap();
    v.save().unwrap();
    v.backup_now().unwrap();
    assert!(older.exists(), "its holder is sealed under the old key");
    assert!(v.backups().unwrap().iter().all(|i| i.validated));
    assert_eq!(titles_in(&newer), ["a"], "still opens with the password");
}
