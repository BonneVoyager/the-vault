//! Untrusted or vanished on-disk state: symlinked package subdirectories, oversized vault
//! files, a primary deleted while unlocked, what a blob-only conflict package may contribute,
//! and what `lock` reports about preserving unsaved state (03 §1, §2, §6, §8).

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::attachment::blob_file_name;
use vault_core::{Item, KdfParams, LockedVault, SecretString, Uuid};
use vault_sync::{
    AttachmentState, BackupKind, LockOutcome, MAX_VAULT_FILE_SIZE, NoopHooks, SyncError, SyncEvent,
    SyncedVault, VAULT_FILE_NAME,
};

const NOW: u64 = 1_700_000_000_000;
const DEV_A: Uuid = Uuid::from_u128(0xA);
const DEADLINE: Duration = Duration::from_secs(20);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn pw() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

/// A saved vault with one item "mail"; returns the package path and the item id.
fn setup() -> (TempDir, PathBuf, SyncedVault, Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let mut v = SyncedVault::create(
        &path,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        Arc::new(NoopHooks),
    )
    .unwrap();
    let item = v
        .edit(|vault| vault.insert(Item::new("mail", Uuid::nil(), NOW), NOW))
        .unwrap();
    v.save().unwrap();
    (dir, path, v, item)
}

fn touch(v: &mut SyncedVault, title: &str) {
    v.edit(|vault| vault.insert(Item::new(title, Uuid::nil(), NOW), NOW))
        .unwrap();
}

fn titles_in(file: &Path) -> Vec<String> {
    let v = LockedVault::parse(&fs::read(file).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    let mut t: Vec<String> = v.items().map(|i| i.title.clone()).collect();
    t.sort();
    t
}

fn events(rx: &Receiver<SyncEvent>) -> Vec<SyncEvent> {
    rx.try_iter().collect()
}

fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    done()
}

fn names(dir: &Path) -> Vec<String> {
    let mut n: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    n.sort();
    n
}

/// A sparse file of `len` bytes, put in place atomically.
fn plant_sized(dst: &Path, len: u64) {
    let tmp = dst.with_file_name(".planting.tmp");
    File::create(&tmp).unwrap().set_len(len).unwrap();
    fs::rename(&tmp, dst).unwrap();
}

// --- #2: symlinked attachments/ and backups/ ---

#[test]
fn symlinked_attachments_dir_is_refused_not_followed() {
    let (_dir, path, mut v, item) = setup();
    let outside = tempfile::tempdir().unwrap();
    // An old unreferenced "blob" outside: orphan cleanup through the link would delete it.
    let bait = outside.path().join(blob_file_name(Uuid::from_u128(7)));
    fs::write(&bait, b"not yours").unwrap();
    File::options()
        .write(true)
        .open(&bait)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - 2 * DAY)
        .unwrap();
    std::os::unix::fs::symlink(outside.path(), path.join("attachments")).unwrap();

    let err = v
        .add_attachment(item, "f", &b"data"[..], 4, NOW + 1)
        .unwrap_err();
    assert!(matches!(err, SyncError::UnsafePackageDir(_)), "{err:?}");

    v.set_prune_clock_offset_for_tests(3 * DAY);
    touch(&mut v, "later");
    v.save().unwrap();
    assert_eq!(
        names(outside.path()),
        vec![blob_file_name(Uuid::from_u128(7))]
    );
    assert!(bait.exists());
}

#[test]
fn symlinked_backups_dir_is_refused_and_lock_reports_unpreserved() {
    let (_dir, path, mut v, _item) = setup();
    let outside = tempfile::tempdir().unwrap();
    // The first save already took a snapshot; swap the real directory for a link.
    fs::remove_dir_all(path.join("backups")).unwrap();
    std::os::unix::fs::symlink(outside.path(), path.join("backups")).unwrap();
    let rx = v.subscribe();

    assert!(matches!(v.backups(), Err(SyncError::UnsafePackageDir(_))));
    assert!(matches!(
        v.backup_now(),
        Err(SyncError::UnsafePackageDir(_))
    ));

    touch(&mut v, "unsaved");
    match v.lock() {
        LockOutcome::Unpreserved(SyncError::UnsafePackageDir(p)) => {
            assert_eq!(p, path.join("backups"));
        }
        other => panic!("{other:?}"),
    }
    assert!(v.vault().is_none(), "locks regardless");
    assert!(
        events(&rx)
            .iter()
            .any(|e| matches!(e, SyncEvent::Error(m) if m.contains("could not be preserved")))
    );
    assert!(
        names(outside.path()).is_empty(),
        "nothing written through the link"
    );
}

#[test]
fn backups_dir_that_is_a_file_is_refused() {
    let (_dir, path, mut v, _item) = setup();
    fs::remove_dir_all(path.join("backups")).unwrap();
    fs::write(path.join("backups"), b"x").unwrap();
    assert!(matches!(
        v.backup_now(),
        Err(SyncError::UnsafePackageDir(_))
    ));
}

// --- #19: lock outcome ---

#[test]
fn lock_outcome_clean_and_snapshotted() {
    let (_dir, path, mut v, _item) = setup();
    assert!(matches!(v.lock(), LockOutcome::Clean));
    // Already locked.
    assert!(matches!(v.lock(), LockOutcome::Clean));

    v.unlock(&pw()).unwrap();
    touch(&mut v, "unsaved");
    let LockOutcome::Snapshotted(p) = v.lock() else {
        panic!("dirty lock must snapshot");
    };
    assert!(p.starts_with(path.join("backups")));
    let listed = v.backups().unwrap();
    assert!(
        listed
            .iter()
            .any(|b| b.path == p && b.kind == BackupKind::Unsaved)
    );
    assert_eq!(titles_in(&p), vec!["mail", "unsaved"]);
}

// --- #3: oversized vault files ---

#[test]
fn oversized_primary_is_refused_by_open() {
    let (_dir, path, v, _item) = setup();
    drop(v);
    plant_sized(&path.join(VAULT_FILE_NAME), MAX_VAULT_FILE_SIZE + 1);
    let err = SyncedVault::open(&path, DEV_A, Arc::new(NoopHooks)).unwrap_err();
    assert!(matches!(err, SyncError::PrimaryTooLarge(_)), "{err:?}");
}

#[test]
fn oversized_primary_seen_by_the_watcher_is_treated_as_corrupt() {
    let (_dir, path, mut v, _item) = setup();
    v.start_watching().unwrap();
    let rx = v.subscribe();
    let file = path.join(VAULT_FILE_NAME);
    plant_sized(&file, MAX_VAULT_FILE_SIZE + 1);
    assert!(wait_until(|| {
        v.poll();
        v.is_dirty()
    }));
    let seen = events(&rx);
    assert!(seen.contains(&SyncEvent::CorruptOnDisk), "{seen:?}");
    assert!(!seen.iter().any(|e| matches!(e, SyncEvent::Merged(_))));
    // Not adopted: ours is intact and rewrites the file.
    assert!(v.vault().is_some());
    v.save().unwrap();
    assert_eq!(titles_in(&file), vec!["mail"]);
    // Repeated events for our own rewrite report nothing new.
    for _ in 0..10 {
        v.poll();
        thread::sleep(Duration::from_millis(50));
    }
    assert!(!events(&rx).contains(&SyncEvent::CorruptOnDisk));
}

#[test]
fn oversized_primary_without_watcher_is_overwritten_by_save() {
    let (_dir, path, mut v, _item) = setup();
    touch(&mut v, "new");
    plant_sized(&path.join(VAULT_FILE_NAME), MAX_VAULT_FILE_SIZE + 1);
    v.save().unwrap();
    assert_eq!(titles_in(&path.join(VAULT_FILE_NAME)), vec!["mail", "new"]);
}

#[test]
fn oversized_backup_is_refused_by_restore() {
    let (_dir, path, mut v, _item) = setup();
    let snap = v.backup_now().unwrap();
    plant_sized(&snap, MAX_VAULT_FILE_SIZE + 1);
    let err = v.restore_from(&snap, &pw()).unwrap_err();
    assert!(matches!(err, SyncError::PrimaryTooLarge(_)), "{err:?}");
    assert_eq!(titles_in(&path.join(VAULT_FILE_NAME)), vec!["mail"]);
}

// --- #5: primary deleted while unlocked ---

#[test]
fn deleted_primary_seen_by_the_watcher_marks_dirty_once_and_save_recreates_it() {
    let (_dir, path, mut v, _item) = setup();
    v.start_watching().unwrap();
    let rx = v.subscribe();
    let file = path.join(VAULT_FILE_NAME);
    fs::remove_file(&file).unwrap();
    assert!(wait_until(|| {
        v.poll();
        v.is_dirty()
    }));
    // A second deletion event (a sibling file touched in the package) does not repeat it.
    fs::write(path.join("unrelated"), b"x").unwrap();
    for _ in 0..10 {
        v.poll();
        thread::sleep(Duration::from_millis(50));
    }
    // The save's own pre-write read sees it missing again: still one report.
    v.save().unwrap();
    assert!(!v.is_dirty());
    let seen = events(&rx);
    assert_eq!(
        seen.iter()
            .filter(|e| **e == SyncEvent::PrimaryMissing)
            .count(),
        1,
        "{seen:?}"
    );
    assert_eq!(titles_in(&file), vec!["mail"]);
}

#[test]
fn deleted_clean_primary_without_watcher_is_snapshotted_on_lock() {
    let (_dir, path, mut v, _item) = setup();
    let rx = v.subscribe();
    fs::remove_file(path.join(VAULT_FILE_NAME)).unwrap();
    let LockOutcome::Snapshotted(p) = v.lock() else {
        panic!("a vault whose primary is gone must be preserved");
    };
    assert_eq!(titles_in(&p), vec!["mail"]);
    assert!(events(&rx).contains(&SyncEvent::PrimaryMissing));
}

#[test]
fn unlock_over_a_deleted_primary_marks_dirty() {
    let (_dir, path, mut v, _item) = setup();
    assert!(matches!(v.lock(), LockOutcome::Clean));
    let file = path.join(VAULT_FILE_NAME);
    fs::remove_file(&file).unwrap();
    let rx = v.subscribe();
    v.unlock(&pw()).unwrap();
    assert!(v.is_dirty());
    assert!(events(&rx).contains(&SyncEvent::PrimaryMissing));
    v.save().unwrap();
    assert_eq!(titles_in(&file), vec!["mail"]);
}

// --- #18: blob-only conflict package ---

/// A remnant package (no `vault.bin`) offers three blobs: one our items reference (copied),
/// one nobody references (ignored), and one we reference but padded past its sealed size
/// (skipped).
#[test]
fn blob_only_conflict_package_contributes_only_referenced_right_sized_blobs() {
    let (dir, _path, mut v, item) = setup();
    let wanted = v
        .add_attachment(item, "a", &b"wanted"[..], 6, NOW + 1)
        .unwrap();
    let padded = v
        .add_attachment(item, "b", &b"padded"[..], 6, NOW + 2)
        .unwrap();
    v.save().unwrap();
    let blob = |id| v.attachments_dir().join(blob_file_name(id));
    let wanted_bytes = fs::read(blob(wanted)).unwrap();
    let mut padded_bytes = fs::read(blob(padded)).unwrap();
    padded_bytes.push(0);
    fs::remove_file(blob(wanted)).unwrap();
    fs::remove_file(blob(padded)).unwrap();
    let stranger = Uuid::from_u128(0x5);

    let remnant = dir.path().join("test 2.vault");
    let staging = dir.path().join(".staging");
    let att = staging.join("attachments");
    fs::create_dir_all(&att).unwrap();
    fs::write(att.join(blob_file_name(stranger)), b"unreferenced").unwrap();
    fs::write(att.join(blob_file_name(padded)), &padded_bytes).unwrap();
    fs::write(att.join(blob_file_name(wanted)), &wanted_bytes).unwrap();
    v.start_watching().unwrap();
    fs::rename(&staging, &remnant).unwrap();

    assert!(wait_until(|| {
        v.poll();
        v.attachment_state(wanted) == AttachmentState::Present
    }));
    for _ in 0..10 {
        v.poll();
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(v.attachment_state(padded), AttachmentState::Missing);
    assert_eq!(v.attachment_state(stranger), AttachmentState::Missing);
    assert_eq!(names(&v.attachments_dir()), vec![blob_file_name(wanted)]);
    assert!(remnant.exists());
}

// --- review follow-ups ---

/// While the primary is missing, a peer's file lands between the save's pre-write read and its
/// write: the no-replace write refuses (`AlreadyExists`), we stay dirty, and the next save
/// merges both.
#[test]
fn recreating_a_missing_primary_never_clobbers_a_peer_file_that_lands_meanwhile() {
    let (dir, path, mut v, _item) = setup();
    let file = path.join(VAULT_FILE_NAME);
    // The peer's version: our file plus an item of its own, prepared in a staging package.
    let staging = dir.path().join("staging");
    fs::create_dir(&staging).unwrap();
    fs::copy(&file, staging.join(VAULT_FILE_NAME)).unwrap();
    let mut peer = SyncedVault::open(&staging, Uuid::from_u128(0xB), Arc::new(NoopHooks)).unwrap();
    peer.unlock(&pw()).unwrap();
    touch(&mut peer, "peer");
    peer.save().unwrap();
    drop(peer);
    let peer_bytes = fs::read(staging.join(VAULT_FILE_NAME)).unwrap();

    fs::remove_file(&file).unwrap();
    touch(&mut v, "ours");
    let landing = file.clone();
    vault_sync::before_next_primary_write_for_tests(move || {
        let tmp = landing.with_file_name(".peer.tmp");
        fs::write(&tmp, &peer_bytes).unwrap();
        fs::rename(&tmp, &landing).unwrap();
    });
    let err = v.save().unwrap_err();
    assert!(matches!(err, SyncError::AlreadyExists(_)), "{err:?}");
    assert!(v.is_dirty());
    assert_eq!(titles_in(&file), vec!["mail", "peer"], "peer file kept");

    v.save().unwrap();
    assert!(!v.is_dirty());
    assert_eq!(titles_in(&file), vec!["mail", "ours", "peer"]);
}

/// A second dirty lock whose state the newest Unsaved file already holds points at that file
/// instead of writing another.
#[test]
fn second_lock_reuses_a_covering_unsaved_file() {
    let (_dir, _path, mut v, _item) = setup();
    touch(&mut v, "unsaved");
    let LockOutcome::Snapshotted(first) = v.lock() else {
        panic!("dirty lock must snapshot");
    };
    v.unlock(&pw()).unwrap();
    // Dirty, but with nothing the first Unsaved file lacks.
    v.edit(|_| ()).unwrap();
    let unsaved = |v: &SyncedVault| {
        v.backups()
            .unwrap()
            .into_iter()
            .filter(|b| b.kind == BackupKind::Unsaved)
            .count()
    };
    assert_eq!(unsaved(&v), 1);
    match v.lock() {
        LockOutcome::Snapshotted(p) => assert_eq!(p, first),
        other => panic!("{other:?}"),
    }
    assert_eq!(unsaved(&v), 1, "no second file written");
}

/// A save whose directory fsync fails (EIO) reports the error and stays dirty; the next save
/// succeeds and the file holds our state throughout.
#[test]
fn save_after_a_dir_fsync_failure_stays_dirty_and_retries() {
    let (_dir, path, mut v, _item) = setup();
    let file = path.join(VAULT_FILE_NAME);
    touch(&mut v, "new");
    vault_sync::fail_next_dir_syncs_for_tests(1);
    let err = v.save().unwrap_err();
    assert!(
        matches!(&err, SyncError::Io { source, .. } if source.raw_os_error() == Some(5)),
        "{err:?}"
    );
    assert!(v.is_dirty());
    // The rename happened; not rolled back.
    assert_eq!(titles_in(&file), vec!["mail", "new"]);

    v.save().unwrap();
    assert!(!v.is_dirty());
    assert_eq!(titles_in(&file), vec!["mail", "new"]);
}

/// Only the directory fsync after writing the Unsaved file failed: the bytes are on disk, so
/// the outcome is `Snapshotted` (with an Error event), not `Unpreserved`.
#[test]
fn lock_whose_unsaved_backup_is_not_confirmed_durable_still_reports_snapshotted() {
    let (_dir, _path, mut v, _item) = setup();
    let rx = v.subscribe();
    touch(&mut v, "unsaved");
    vault_sync::fail_next_dir_syncs_for_tests(1);
    let LockOutcome::Snapshotted(p) = v.lock() else {
        panic!("written backup must count as snapshotted");
    };
    assert_eq!(titles_in(&p), vec!["mail", "unsaved"]);
    assert!(
        events(&rx)
            .iter()
            .any(|e| matches!(e, SyncEvent::Error(m) if m.contains("may not be durable")))
    );
}
