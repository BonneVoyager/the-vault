//! Security review 2026-11-26 L-05: a planted `backups` / `attachments` entry must not cost
//! the session's edits (local fallback copy) and can be quarantined (`repair_package`).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use vault_core::format::{MAGIC, PREFIX_LEN};
use vault_core::{Item, KdfParams, SecretString, Uuid};
use vault_sync::{
    BackupKind, LockOutcome, NoopHooks, SyncError, SyncEvent, SyncedVault, VAULT_FILE_NAME,
};

const NOW: u64 = 1_700_000_000_000;

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

/// A saved package `test.vault` (item "a") whose `backups/` was replaced by a plain file.
fn planted() -> (TempDir, PathBuf, SyncedVault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let mut v = SyncedVault::create(
        &path,
        &pw(),
        KdfParams::for_tests(),
        Uuid::from_u128(0xD0D0),
        Arc::new(NoopHooks),
    )
    .unwrap();
    insert(&mut v, "a");
    v.save().unwrap();
    fs::remove_dir_all(path.join("backups")).unwrap();
    fs::write(path.join("backups"), b"planted").unwrap();
    (dir, path, v)
}

fn insert(v: &mut SyncedVault, title: &str) {
    v.edit(|vault| vault.insert(Item::new(title, Uuid::nil(), NOW), NOW))
        .unwrap();
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

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Names of the package's entries, sorted.
fn entries(path: &Path) -> Vec<String> {
    let mut n: Vec<String> = fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    n.sort();
    n
}

fn preserved(outcome: LockOutcome) -> PathBuf {
    match outcome {
        LockOutcome::Snapshotted(p) => p,
        other => panic!("expected Snapshotted, got {other:?}"),
    }
}

#[test]
fn unsaved_edits_go_to_the_fallback_folder_and_round_trip() {
    let (_dir, path, mut v) = planted();
    let fb = tempfile::tempdir().unwrap();
    let base = fb.path().join("unsaved");
    v.set_fallback_dir(Some(base.clone()));
    let rx = v.subscribe();
    let home = base.join(v.locked_summary().vault_id.to_string());

    insert(&mut v, "b");
    let first = preserved(v.lock());
    assert_eq!(first.parent().unwrap(), home);
    assert!(
        rx.try_iter()
            .any(|e| e == SyncEvent::BackupTaken(first.clone()))
    );
    assert_eq!(mode(&first), 0o600);
    assert_eq!(mode(&home), 0o700);
    let name = first.file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("test-") && name.ends_with("-unsaved.vault.bin"),
        "{name}"
    );
    // The planted backups/ is an error for the listing (the app offers repair), never
    // hidden behind the fallback copies.
    let err = v.backups().unwrap_err();
    assert!(matches!(err, SyncError::UnsafePackageDir(_)), "{err:?}");

    // A second session's edits: a new copy (the first does not hold "c").
    v.unlock(&pw()).unwrap();
    insert(&mut v, "c");
    let second = preserved(v.lock());
    assert_ne!(second, first);
    // The edits were never saved: the primary still holds only "a".
    v.unlock(&pw()).unwrap();
    assert_eq!(titles(&v), ["a"]);

    // Deleting works while backups/ is still planted.
    v.delete_backup(&first).unwrap();
    assert!(!first.exists());
    assert!(
        rx.try_iter()
            .any(|e| e == SyncEvent::BackupDeleted(first.clone()))
    );

    // Restoring needs a usable backups/ (the pre-restore snapshot goes there).
    let err = v.restore_from(&second, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::UnsafePackageDir(_)), "{err:?}");
    assert_eq!(v.repair_package().unwrap().len(), 1);
    let listed = v.backups().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, second);
    assert_eq!(listed[0].kind, BackupKind::Unsaved);
    assert!(listed[0].validated);
    v.restore_from(&second, &pw()).unwrap();
    assert_eq!(titles(&v), ["a", "c"]);
    assert!(path.join("backups").is_dir());
    assert!(second.exists(), "fallback copies are never pruned");
}

#[test]
fn without_a_fallback_folder_the_edits_are_unpreserved() {
    let (_dir, _path, mut v) = planted();
    insert(&mut v, "b");
    match v.lock() {
        LockOutcome::Unpreserved(SyncError::UnsafePackageDir(_)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn repair_quarantines_a_file_and_a_symlink_without_following() {
    let (_dir, path, mut v) = planted();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("keep.bin"), b"outside").unwrap();
    let _ = fs::remove_dir_all(path.join("attachments"));
    std::os::unix::fs::symlink(outside.path(), path.join("attachments")).unwrap();

    let mut moved = v.repair_package().unwrap();
    moved.sort();
    assert_eq!(moved.len(), 2);
    let names: Vec<&str> = moved
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap())
        .collect();
    assert!(
        names[0].starts_with("attachments.quarantined-"),
        "{names:?}"
    );
    assert!(names[1].starts_with("backups.quarantined-"), "{names:?}");
    assert!(
        fs::symlink_metadata(&moved[0])
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&moved[1]).unwrap(), b"planted");
    assert_eq!(
        fs::read(outside.path().join("keep.bin")).unwrap(),
        b"outside"
    );
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);

    insert(&mut v, "b");
    v.save().unwrap();
    assert!(fs::symlink_metadata(path.join("backups")).unwrap().is_dir());
    assert_eq!(v.backups().unwrap().len(), 1);

    // A second plant in the same second gets its own name.
    fs::write(path.join("attachments"), b"again").unwrap();
    let again = v.repair_package().unwrap();
    assert_eq!(again.len(), 1);
    assert!(!moved.contains(&again[0]));
    assert!(moved[0].exists() && again[0].exists());
}

#[test]
fn repair_leaves_a_newer_version_stub_alone() {
    let (_dir, path, mut v) = planted();
    assert!(matches!(v.lock(), LockOutcome::Clean));
    let mut stub = MAGIC.to_vec();
    stub.extend_from_slice(&u16::MAX.to_be_bytes());
    stub.resize(PREFIX_LEN, 0);
    assert_eq!(stub.len(), 10);
    fs::write(path.join(VAULT_FILE_NAME), &stub).unwrap();

    let moved = v.repair_package().unwrap();
    assert_eq!(moved.len(), 1);
    assert_eq!(fs::read(path.join(VAULT_FILE_NAME)).unwrap(), stub);
}

#[test]
fn repair_of_a_healthy_package_changes_nothing() {
    let (_dir, path, mut v) = planted();
    fs::remove_file(path.join("backups")).unwrap();
    insert(&mut v, "b");
    v.save().unwrap();
    let before = entries(&path);
    assert!(before.contains(&"backups".to_owned()));
    assert!(v.repair_package().unwrap().is_empty());
    assert_eq!(entries(&path), before);
}

#[test]
fn restore_and_delete_refuse_paths_outside_both_homes() {
    let (_dir, path, mut v) = planted();
    fs::remove_file(path.join("backups")).unwrap();
    let fb = tempfile::tempdir().unwrap();
    v.set_fallback_dir(Some(fb.path().to_owned()));
    let home = fb.path().join(v.locked_summary().vault_id.to_string());
    fs::create_dir(&home).unwrap();

    let elsewhere = tempfile::tempdir().unwrap();
    let copy = |dir: &Path| {
        let p = dir.join("test-2026-11-27T10-00-00Z-unsaved.vault.bin");
        fs::copy(path.join(VAULT_FILE_NAME), &p).unwrap();
        p
    };
    let candidates = [
        copy(elsewhere.path()),
        copy(fb.path()),
        path.join(VAULT_FILE_NAME),
    ];
    for p in &candidates {
        let err = v.restore_from(p, &pw()).unwrap_err();
        assert!(matches!(err, SyncError::NotABackup(_)), "{p:?}: {err:?}");
        let err = v.delete_backup(p).unwrap_err();
        assert!(matches!(err, SyncError::NotABackup(_)), "{p:?}: {err:?}");
        assert!(p.exists());
    }
    // A symlink inside the fallback home is not followed either.
    let link = home.join("test-2026-11-27T11-00-00Z-unsaved.vault.bin");
    std::os::unix::fs::symlink(&candidates[0], &link).unwrap();
    assert!(v.backups().unwrap().iter().all(|b| b.path != link));
    let err = v.delete_backup(&link).unwrap_err();
    assert!(matches!(err, SyncError::NotABackup(_)), "{err:?}");
    let err = v.restore_from(&link, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::UnsafePackageEntry(_)), "{err:?}");
    assert!(candidates[0].exists());
}

#[test]
fn a_symlinked_vault_id_folder_is_never_used() {
    let (_dir, path, mut v) = planted();
    fs::remove_file(path.join("backups")).unwrap();
    let fb = tempfile::tempdir().unwrap();
    v.set_fallback_dir(Some(fb.path().to_owned()));
    let home = fb.path().join(v.locked_summary().vault_id.to_string());
    let real = tempfile::tempdir().unwrap();
    let copy = real
        .path()
        .join("test-2026-11-27T10-00-00Z-unsaved.vault.bin");
    fs::copy(path.join(VAULT_FILE_NAME), &copy).unwrap();
    std::os::unix::fs::symlink(real.path(), &home).unwrap();
    let through = home.join(copy.file_name().unwrap());

    assert!(v.backups().unwrap().iter().all(|b| b.path != through));
    let err = v.restore_from(&through, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::UnsafePackageDir(_)), "{err:?}");
    let err = v.delete_backup(&through).unwrap_err();
    assert!(matches!(err, SyncError::UnsafePackageDir(_)), "{err:?}");
    assert!(copy.exists());
}

/// The parent is canonicalised before the containment check: `..` that still lands in
/// `backups/` is that backup; one that leaves it is refused.
#[test]
fn dot_dot_paths_are_judged_after_canonicalisation() {
    let (_dir, path, mut v) = planted();
    fs::remove_file(path.join("backups")).unwrap();
    insert(&mut v, "b");
    v.save().unwrap();
    let snap = v.backup_now().unwrap();
    let name = snap.file_name().unwrap();

    let escaping = path.join("backups").join("..").join(VAULT_FILE_NAME);
    let err = v.restore_from(&escaping, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::NotABackup(_)), "{err:?}");
    let err = v.delete_backup(&escaping).unwrap_err();
    assert!(matches!(err, SyncError::NotABackup(_)), "{err:?}");

    let inside = path.join("backups").join("..").join("backups").join(name);
    v.restore_from(&inside, &pw()).unwrap();
    assert_eq!(titles(&v), ["a", "b"]);
}

#[test]
fn a_snapshot_refused_by_a_planted_backups_entry_is_typed() {
    let (_dir, path, mut v) = planted();
    // First save after unlock: a snapshot is due and refused; the save itself succeeds.
    let _ = v.lock();
    v.unlock(&pw()).unwrap();
    let rx = v.subscribe();
    insert(&mut v, "b");
    v.save().unwrap();
    let events: Vec<SyncEvent> = rx.try_iter().collect();
    let failed: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SyncEvent::BackupFailed {
                unsafe_dir,
                message,
            } => Some((*unsafe_dir, message.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(failed.len(), 1, "{events:?}");
    assert!(failed[0].0, "UnsafePackageDir is flagged");
    let expected = format!(
        "backup failed: {}",
        SyncError::UnsafePackageDir(path.join("backups"))
    );
    assert_eq!(failed[0].1, expected);
    assert!(!events.iter().any(|e| matches!(e, SyncEvent::Error(_))));
}
