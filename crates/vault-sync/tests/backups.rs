//! Snapshots, retention wiring and restore through `SyncedVault` (03 §4, §8, §9).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::{Item, ItemKind, KdfParams, SecretString, Uuid};
use vault_sync::{CloudError, CloudHooks, NoopHooks, SyncError, SyncEvent, SyncedVault};

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
    v.edit(|vault| vault.insert(Item::new(ItemKind::Login, title, Uuid::nil(), NOW), NOW))
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

fn backups_dir(dir: &Path) -> PathBuf {
    dir.join("test.vault.backups")
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
    assert_ne!(fs::read(&taken[0]).unwrap(), fs::read(&path).unwrap());
    assert_eq!(list[0].size, fs::metadata(&taken[0]).unwrap().len());

    let name = taken[0].file_name().unwrap().to_str().unwrap().to_owned();
    assert!(
        name.starts_with("test-") && name.ends_with("Z.vault"),
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
    assert_eq!(fs::read(&taken[1]).unwrap(), fs::read(&path).unwrap());

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
    v.lock();
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
    v.lock();
    let rx = v.subscribe();
    let snap = v.backup_now().unwrap();
    assert_eq!(fs::read(&snap).unwrap(), fs::read(&path).unwrap());
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
    let before = fs::read(&path).unwrap();
    insert_item(&mut v, "unsaved");
    let rx = v.subscribe();

    v.restore_from(&snap, &pw()).unwrap();

    assert_eq!(fs::read(&path).unwrap(), snap_bytes);
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
    v.lock();
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
    let before = fs::read(&path).unwrap();
    let rx = v.subscribe();

    let err = v
        .restore_from(&snap, &SecretString::new("wrong".to_owned()))
        .unwrap_err();
    assert!(matches!(err, SyncError::Vault(_)), "{err:?}");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(titles(&v), ["a", "b", "unsaved"]);
    assert!(v.is_dirty());
    assert!(backups_taken(&rx).is_empty());
    assert_eq!(v.backups().unwrap().len(), 1);
}

#[test]
fn restore_rejects_a_different_vault() {
    let (_dir, path, mut v) = setup();
    let (_dir2, other_path, _other) = setup();
    let before = fs::read(&path).unwrap();
    let err = v.restore_from(&other_path, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::ForeignVault { .. }), "{err:?}");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(v.backups().unwrap().is_empty());
}

#[test]
fn restore_works_from_locked_and_over_a_corrupt_primary() {
    let (_dir, path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    let snap = v.backups().unwrap()[0].path.clone();
    v.lock();
    fs::write(&path, b"garbage").unwrap();

    v.restore_from(&snap, &pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);
    assert_eq!(fs::read(&path).unwrap(), fs::read(&snap).unwrap());
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
    let conflict = b.join("conflict-2026-10-28T14-03-11Z-test (Mac's conflicted copy).vault");
    fs::write(&conflict, b"x").unwrap();
    fs::write(b.join("notes.txt"), b"x").unwrap();

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
    let old_a = b.join("test-2020-01-05T00-00-00Z.vault");
    let old_b = b.join("test-2020-01-20T00-00-00Z.vault");
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
    let before = fs::read(&path).unwrap();
    let is_timeout = |e: SyncError| matches!(e, SyncError::Cloud(CloudError::Timeout));

    // Primary evicted: backup_now and restore_from both fail before touching anything.
    *hooks.0.lock().unwrap() = Some(path.clone());
    assert!(is_timeout(v.backup_now().unwrap_err()));
    assert!(is_timeout(v.restore_from(&snap, &pw()).unwrap_err()));
    // Backup evicted: restore_from fails too.
    *hooks.0.lock().unwrap() = Some(snap.clone());
    assert!(is_timeout(v.restore_from(&snap, &pw()).unwrap_err()));

    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(titles(&v), ["a", "b"]);
    assert_eq!(v.backups().unwrap().len(), 1);
}

#[test]
fn fresh_conflict_file_does_not_suppress_hourly_snapshot() {
    let (dir, _path, mut v) = setup();
    insert_item(&mut v, "a");
    v.save().unwrap();
    // Turn our seconds-old snapshot into a just-absorbed conflict copy, leaving no snapshot of
    // our own (as if the last one were over an hour old and pruned).
    let ours = v.backups().unwrap()[0].path.clone();
    let name = ours.file_name().unwrap().to_str().unwrap();
    let stamp = &name["test-".len()..name.len() - ".vault".len()];
    let conflict =
        backups_dir(dir.path()).join(format!("conflict-{stamp}-test (conflicted copy).vault"));
    fs::rename(&ours, &conflict).unwrap();
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
    v.lock();
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
