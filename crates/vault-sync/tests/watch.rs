//! Watcher-driven reconciliation (03 §1, §3, §6, §9): two instances on one package, conflicted
//! packages, corruption, changes while locked, key rotation by another device.
//!
//! Flakiness guards: every wait is a deadline loop around `poll()` (never a bare sleep for a
//! positive assertion); planted files are written to a hidden tmp name and renamed in, and
//! planted packages are filled under a hidden name and renamed in, so the watcher never sees a
//! half-written `vault.bin`; the only fixed waits are the negative checks, which wait several
//! debounce windows.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::format::VaultFile;
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, KdfParams, LockedVault, SecretString, Uuid,
};
use vault_sync::{
    BackupKind, DEBOUNCE, NoopHooks, SaveBlocked, SyncError, SyncEvent, SyncedVault,
    VAULT_FILE_NAME,
};

const T0: u64 = 1_700_000_000_000;
const DEADLINE: Duration = Duration::from_secs(20);

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

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

const DEV_A: Uuid = Uuid::from_u128(0xA);
const DEV_B: Uuid = Uuid::from_u128(0xB);

/// Collects events from one subscription across polls.
struct Events {
    rx: Receiver<SyncEvent>,
    seen: Vec<SyncEvent>,
}

impl Events {
    fn new(v: &SyncedVault) -> Self {
        Self {
            rx: v.subscribe(),
            seen: Vec::new(),
        }
    }
    fn pump(&mut self) {
        self.seen.extend(self.rx.try_iter());
    }
    fn any(&self, f: impl Fn(&SyncEvent) -> bool) -> bool {
        self.seen.iter().any(f)
    }
    fn count(&self, f: impl Fn(&SyncEvent) -> bool) -> usize {
        self.seen.iter().filter(|e| f(e)).count()
    }
}

/// Poll-and-check until `done` holds or the deadline passes.
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

/// Device A creates the vault with one login (username + password), saves, and device B opens
/// and unlocks it. Neither is watching yet. The returned path is the package's `vault.bin`.
fn two_devices() -> (TempDir, PathBuf, SyncedVault, SyncedVault, Uuid) {
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
    let id = a
        .edit(|v| {
            let mut item = Item::new("mail", Uuid::nil(), T0);
            item.fields
                .push(Field::new("username", FieldKind::Text, secret("alice"), T0));
            item.fields.push(Field::new(
                "password",
                FieldKind::Password,
                secret("hunter2"),
                T0,
            ));
            v.insert(item, T0)
        })
        .unwrap();
    a.save().unwrap();
    let mut b = SyncedVault::open(&package, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    (dir, package.join(VAULT_FILE_NAME), a, b, id)
}

/// The id of item `id`'s field labelled `name`, resolved once; every comparison after that
/// goes by id (03 §5: fields are identified by `field.id`, never by name).
fn fid(v: &SyncedVault, id: Uuid, name: &str) -> Uuid {
    v.vault().unwrap().get(id).unwrap().field(name).unwrap().id
}

/// Value of field `field_id` of live item `id`.
fn field(v: &SyncedVault, id: Uuid, field_id: Uuid) -> Option<String> {
    let item = v.vault()?.get(id)?;
    if item.is_deleted() {
        return None;
    }
    Some(item.field_by_id(field_id)?.value.expose_secret().clone())
}

fn is_deleted(v: &SyncedVault, id: Uuid) -> bool {
    v.vault().unwrap().get(id).is_some_and(|i| i.is_deleted())
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

/// Write `bytes` at `dst` atomically via a hidden tmp name the watcher ignores.
fn plant(dst: &Path, bytes: &[u8]) {
    let tmp = dst.with_file_name(".planting.tmp");
    fs::write(&tmp, bytes).unwrap();
    fs::rename(&tmp, dst).unwrap();
}

/// Put a package holding `vault.bin` = `bytes` at `dst` in one rename (filled under a hidden
/// name first). An existing package there is swapped out in the same instant and deleted.
fn plant_package(dst: &Path, bytes: &[u8]) {
    let staging = dst.with_file_name(".staging-package");
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join(VAULT_FILE_NAME), bytes).unwrap();
    let old = dst.with_file_name(".old-package");
    let replaced = dst.exists();
    if replaced {
        fs::rename(dst, &old).unwrap();
    }
    fs::rename(&staging, dst).unwrap();
    if replaced {
        fs::remove_dir_all(&old).unwrap();
    }
}

/// Poll for several debounce windows; returns the number of signals drained.
fn drain_for(v: &mut SyncedVault, windows: u32) -> usize {
    let mut drained = 0;
    let until = Instant::now() + DEBOUNCE * windows;
    while Instant::now() < until {
        drained += v.poll();
        thread::sleep(Duration::from_millis(25));
    }
    drained
}

fn on_disk(path: &Path) -> LockedVault {
    LockedVault::parse(&fs::read(path).unwrap()).unwrap()
}

fn merged(e: &SyncEvent) -> bool {
    matches!(e, SyncEvent::Merged(_))
}

#[test]
fn synced_vault_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<SyncedVault>();
}

#[test]
fn two_devices_converge_on_field_edits() {
    let (_dir, path, mut a, mut b, id) = two_devices();
    a.start_watching().unwrap();
    b.start_watching().unwrap();
    let (mut ea, mut eb) = (Events::new(&a), Events::new(&b));
    let (user, pass) = (fid(&a, id, "username"), fid(&a, id, "password"));

    a.edit(|v| v.set_field(id, user, secret("alice@a"), T0 + 1_000))
        .unwrap()
        .unwrap();
    a.save().unwrap();
    b.edit(|v| v.set_field(id, pass, secret("b-pass"), T0 + 2_000))
        .unwrap()
        .unwrap();
    b.save().unwrap();

    let both = |v: &SyncedVault| {
        field(v, id, user).as_deref() == Some("alice@a")
            && field(v, id, pass).as_deref() == Some("b-pass")
    };
    assert!(
        wait_until(|| {
            a.poll();
            b.poll();
            ea.pump();
            eb.pump();
            both(&a) && both(&b)
        }),
        "did not converge"
    );
    // The file on disk carries both edits too (whoever merged last saved it).
    assert!(wait_until(|| {
        a.poll();
        b.poll();
        let mut disk = on_disk(&path).unlock(&pw()).unwrap();
        disk.set_device_id(DEV_A);
        let item = disk.get(id).unwrap();
        item.field_by_id(user).unwrap().value.expose_secret() == "alice@a"
            && item.field_by_id(pass).unwrap().value.expose_secret() == "b-pass"
    }));
    ea.pump();
    eb.pump();
    assert!(ea.any(merged), "A got no Merged");
    assert!(eb.any(merged), "B got no Merged");
    assert!(!a.is_dirty() && !b.is_dirty());
}

fn delete_vs_edit(delete_at: u64, edit_at: u64) -> (SyncedVault, SyncedVault, Uuid, Uuid, TempDir) {
    let (dir, _path, mut a, mut b, id) = two_devices();
    let pass = fid(&a, id, "password");
    a.start_watching().unwrap();
    b.start_watching().unwrap();
    // Order of the writes on disk is fixed (A then B); the timestamps decide the winner.
    a.edit(|v| v.delete(id, delete_at)).unwrap().unwrap();
    a.save().unwrap();
    b.edit(|v| v.set_field(id, pass, secret("edited"), edit_at))
        .unwrap()
        .unwrap();
    b.save().unwrap();
    (a, b, id, pass, dir)
}

#[test]
fn edit_after_delete_wins() {
    let (mut a, mut b, id, pass, _dir) = delete_vs_edit(T0 + 1_000, T0 + 2_000);
    assert!(wait_until(|| {
        a.poll();
        b.poll();
        field(&a, id, pass).as_deref() == Some("edited")
            && field(&b, id, pass).as_deref() == Some("edited")
    }));
}

#[test]
fn delete_after_edit_wins() {
    let (mut a, mut b, id, _pass, _dir) = delete_vs_edit(T0 + 2_000, T0 + 1_000);
    assert!(wait_until(|| {
        a.poll();
        b.poll();
        is_deleted(&a, id) && is_deleted(&b, id)
    }));
}

#[test]
fn own_save_is_not_merged() {
    let (_dir, _path, mut a, _b, id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let user = fid(&a, id, "username");
    a.edit(|v| v.set_field(id, user, secret("x"), T0 + 1_000))
        .unwrap()
        .unwrap();
    a.save().unwrap();
    let mut drained = 0;
    let until = Instant::now() + DEBOUNCE * 5;
    while Instant::now() < until {
        drained += a.poll();
        thread::sleep(Duration::from_millis(25));
    }
    ea.pump();
    assert!(drained > 0, "watcher never reported our own write");
    assert!(
        ea.seen
            .iter()
            .all(|e| matches!(e, SyncEvent::BackupTaken(_))),
        "{:?}",
        ea.seen
    );
}

/// Item `id`'s fields as `(id, name, value)`, or `None` if the item is gone or deleted.
fn fields_of(v: &SyncedVault, id: Uuid) -> Option<Vec<(Uuid, String, String)>> {
    let item = v.vault()?.get(id)?;
    if item.is_deleted() {
        return None;
    }
    Some(
        item.fields
            .iter()
            .map(|f| (f.id, f.name.clone(), f.value.expose_secret().clone()))
            .collect(),
    )
}

/// Field ids and names only (never values) for assertion messages.
fn names(v: &SyncedVault, id: Uuid) -> Option<Vec<(Uuid, String)>> {
    fields_of(v, id).map(|f| f.into_iter().map(|(i, n, _)| (i, n)).collect())
}

/// Rename field `field_id` of item `id` to `name` through `update` (a rename is an edit of the
/// same field, 02 "update").
fn rename(v: &mut SyncedVault, id: Uuid, field_id: Uuid, name: &str, now: u64) {
    v.edit(|v| {
        v.update(id, now, |item| {
            item.fields
                .iter_mut()
                .find(|f| f.id == field_id)
                .unwrap()
                .name = name.to_owned();
        })
    })
    .unwrap()
    .unwrap();
}

/// Poll both devices until `done` holds on each and neither is dirty.
fn converge(
    a: &mut SyncedVault,
    b: &mut SyncedVault,
    id: Uuid,
    done: impl Fn(&SyncedVault) -> bool,
) {
    assert!(
        wait_until(|| {
            a.poll();
            b.poll();
            done(a) && done(b) && !a.is_dirty() && !b.is_dirty()
        }),
        "did not converge: A {:?} / B {:?}",
        names(a, id),
        names(b, id),
    );
}

/// 03 §5: a rename on A and a value edit on B of the same field stay one field (same id, no
/// "deleted + added" duplicate). Concurrently, the field is merged whole by `modified_at`
/// (the later value edit carries the old name); once B has merged the rename, its next value
/// edit keeps the new name, so both devices end with the new name and the new value.
#[test]
fn rename_and_value_edit_stay_one_field() {
    let (_dir, _path, mut a, mut b, id) = two_devices();
    let pass = fid(&a, id, "password");
    a.start_watching().unwrap();
    b.start_watching().unwrap();

    // Concurrent: A renames at T0+1s, B (not yet aware) edits the value at T0+2s.
    rename(&mut a, id, pass, "pin", T0 + 1_000);
    a.save().unwrap();
    b.edit(|v| v.set_field(id, pass, secret("b-pass"), T0 + 2_000))
        .unwrap()
        .unwrap();
    b.save().unwrap();
    let user = fid(&a, id, "username");
    let expect_lww = |v: &SyncedVault| {
        let Some(f) = fields_of(v, id) else {
            return false;
        };
        f.len() == 2
            && f.iter().any(|(i, ..)| *i == user)
            && f.contains(&(pass, "password".into(), "b-pass".into()))
    };
    converge(&mut a, &mut b, id, expect_lww);

    // Sequential: A renames again, B merges it, then B edits the value.
    rename(&mut a, id, pass, "pin", T0 + 3_000);
    a.save().unwrap();
    assert!(wait_until(|| {
        b.poll();
        fields_of(&b, id).is_some_and(|f| f.iter().any(|(i, n, _)| *i == pass && n == "pin"))
    }));
    b.edit(|v| v.set_field(id, pass, secret("final"), T0 + 4_000))
        .unwrap()
        .unwrap();
    b.save().unwrap();
    let renamed_and_edited = |v: &SyncedVault| {
        let Some(f) = fields_of(v, id) else {
            return false;
        };
        f.len() == 2 && f.contains(&(pass, "pin".into(), "final".into()))
    };
    converge(&mut a, &mut b, id, renamed_and_edited);
}

/// 03 §5 `removed_fields`: A removes a field, B edits it strictly later without having seen the
/// removal; the edit survives on both and the marker is dropped. A then removes it again
/// (after B's edit): it is gone on both and stays gone.
#[test]
fn field_removal_vs_later_edit() {
    let (_dir, _path, mut a, mut b, id) = two_devices();
    let pass = fid(&a, id, "password");
    a.start_watching().unwrap();
    b.start_watching().unwrap();

    a.edit(|v| v.remove_field(id, pass, T0 + 1_000))
        .unwrap()
        .unwrap();
    a.save().unwrap();
    b.edit(|v| v.set_field(id, pass, secret("b-edit"), T0 + 2_000))
        .unwrap()
        .unwrap();
    b.save().unwrap();
    let survived = |v: &SyncedVault| {
        field(v, id, pass).as_deref() == Some("b-edit")
            && v.vault()
                .unwrap()
                .get(id)
                .unwrap()
                .removed_fields
                .iter()
                .all(|t| t.id != pass)
    };
    converge(&mut a, &mut b, id, survived);

    a.edit(|v| v.remove_field(id, pass, T0 + 3_000))
        .unwrap()
        .unwrap();
    a.save().unwrap();
    let gone = |v: &SyncedVault| {
        let item = v.vault().unwrap().get(id).unwrap();
        item.field_by_id(pass).is_none()
            && item.removed_fields.iter().any(|t| t.id == pass)
            && item.field_by_id(fid(v, id, "username")).is_some()
    };
    converge(&mut a, &mut b, id, gone);
    // Stays gone: nothing re-adds it over a few more debounce windows.
    drain_for(&mut a, 3);
    drain_for(&mut b, 3);
    assert!(gone(&a) && gone(&b));
}

/// B's unsaved state (one extra item) written as a sibling package named `name`; A absorbs it.
fn absorb_sibling(name: &str) {
    let (dir, path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = dir.path().join(name);
    plant_package(&copy, &b.vault().unwrap().serialize());

    assert!(
        wait_until(|| {
            a.poll();
            ea.pump();
            ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_)))
        }),
        "{name} not absorbed"
    );
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!copy.exists());
    let moved = ea
        .seen
        .iter()
        .find_map(|e| match e {
            SyncEvent::ConflictAbsorbed(p) => Some(p.clone()),
            _ => None,
        })
        .unwrap();
    let moved_name = moved.file_name().unwrap().to_str().unwrap();
    assert!(moved_name.starts_with("conflict-"), "{moved_name}");
    assert!(moved_name.ends_with(&format!("-{name}")), "{moved_name}");
    assert_eq!(
        moved.parent().unwrap(),
        dir.path().join("test.vault").join("backups")
    );
    // The whole package moved.
    assert!(moved.join(VAULT_FILE_NAME).is_file());
    assert!(
        a.backups()
            .unwrap()
            .iter()
            .any(|i| i.path == moved && i.is_conflict())
    );
    // The merged result is on disk.
    let disk = on_disk(&path).unlock(&pw()).unwrap();
    assert_eq!(disk.items().count(), 2);
    // No attachments, so nothing to wait for.
    drain_for(&mut a, 2);
    ea.pump();
    assert!(!ea.any(|e| matches!(e, SyncEvent::WaitingForBlobs(_))));
}

#[test]
fn dropbox_conflicted_copy_is_absorbed() {
    absorb_sibling("test (Chris's conflicted copy 2026-10-29).vault");
}

#[test]
fn icloud_numbered_copy_is_absorbed() {
    absorb_sibling("test 2.vault");
}

#[test]
fn foreign_vault_sibling_is_left_alone() {
    let (dir, _path, mut a, _b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let other_dir = tempfile::tempdir().unwrap();
    let other_path = other_dir.path().join("other.vault");
    SyncedVault::create(
        &other_path,
        &pw(),
        KdfParams::for_tests(),
        DEV_B,
        Arc::new(NoopHooks),
    )
    .unwrap();
    let bytes = fs::read(other_path.join(VAULT_FILE_NAME)).unwrap();
    let planted = dir.path().join("other.vault");
    plant_package(&planted, &bytes);

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::ForeignVault)
    }));
    assert_eq!(fs::read(planted.join(VAULT_FILE_NAME)).unwrap(), bytes);
    assert!(!ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_))));
    assert_eq!(titles(&a), ["mail"]);
}

#[test]
fn corrupt_primary_is_reported_and_rewritten_on_save() {
    let (_dir, path, mut a, _b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    plant(&path, b"definitely not a vault");

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::CorruptOnDisk)
    }));
    assert_eq!(titles(&a), ["mail"]);
    assert!(a.is_dirty());
    a.save().unwrap();
    let disk = on_disk(&path).unlock(&pw()).unwrap();
    assert_eq!(disk.items().count(), 1);
}

#[test]
fn change_while_locked_is_seen_at_unlock() {
    let (_dir, _path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    let _ = a.lock();
    let mut ea = Events::new(&a);
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    b.save().unwrap();

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::ChangedWhileLocked)
    }));
    a.unlock(&pw()).unwrap();
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!a.is_dirty());
}

#[test]
fn key_rotation_elsewhere_reports_rotation_and_reverify_merges() {
    let (_dir, path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    b.start_watching().unwrap();
    let mut ea = Events::new(&a);
    b.edit(|v| v.rotate_vault_key(&pw(), wall_ms()))
        .unwrap()
        .unwrap();
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    b.save().unwrap();
    let rotated = fs::read(&path).unwrap();

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::KeyRotatedOnDisk)
    }));
    assert!(!ea.any(|e| *e == SyncEvent::KeyMismatch));
    // In-memory untouched, disk untouched, saving refused.
    assert_eq!(titles(&a), ["mail"]);
    a.edit(|v| v.insert(Item::new("from a", Uuid::nil(), T0), T0))
        .unwrap();
    assert!(matches!(a.save(), Err(SyncError::KeyMismatch)));
    assert_eq!(fs::read(&path).unwrap(), rotated);

    // Re-entering the password adopts the rotated vault and keeps A's unsaved item.
    a.unlock(&pw()).unwrap();
    assert_eq!(titles(&a), ["from a", "from b", "mail"]);
    assert!(a.is_dirty());
    a.save().unwrap();
    // B (holding the rotated key) can open what A wrote.
    assert!(wait_until(|| {
        b.poll();
        titles(&b) == ["from a", "from b", "mail"]
    }));
}

#[test]
fn conflict_seen_while_locked_is_absorbed_on_unlock() {
    let (dir, _path, mut a, mut b, _id) = two_devices();
    let _ = a.lock();
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = dir.path().join("test 2.vault");
    plant_package(&copy, &b.vault().unwrap().serialize());

    // Starting the watcher queues existing siblings; the locked poll defers them.
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    assert!(wait_until(|| a.poll() > 0));
    ea.pump();
    assert!(copy.exists());
    assert!(!ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_))));

    a.unlock(&pw()).unwrap();
    ea.pump();
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!copy.exists());
    assert_eq!(ea.count(|e| matches!(e, SyncEvent::ConflictAbsorbed(_))), 1);
}

#[test]
fn generic_name_sibling_of_our_vault_is_absorbed() {
    absorb_sibling("laptop export.vault");
}

#[test]
fn newer_format_primary_is_reported_and_never_overwritten() {
    let (_dir, path, mut a, _b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let mut newer = fs::read(&path).unwrap();
    newer[4..6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    plant(&path, &newer);

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::SaveBlocked(SaveBlocked::NewerVersion(0xFFFF)))
    }));
    assert_eq!(titles(&a), ["mail"]);
    assert!(
        !a.is_dirty(),
        "a newer file must not be scheduled for rewrite"
    );
    assert!(matches!(
        a.save(),
        Err(SyncError::SaveBlocked(SaveBlocked::NewerVersion(0xFFFF)))
    ));
    assert_eq!(fs::read(&path).unwrap(), newer);
}

#[test]
fn tampered_primary_keeps_in_memory_and_is_rewritten() {
    let (_dir, path, mut a, _b, _id) = two_devices();
    a.edit(|v| v.insert(Item::new("second", Uuid::nil(), T0), T0))
        .unwrap();
    a.save().unwrap();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    // A damaged second record: the cached key authenticates the first, so this is reported
    // as tampering rather than a key mismatch.
    let mut file = VaultFile::parse(&fs::read(&path).unwrap()).unwrap();
    file.items[1].ct[0] ^= 0x01;
    plant(&path, &file.to_bytes());

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::CorruptOnDisk)
    }));
    assert!(!ea.any(|e| *e == SyncEvent::KeyMismatch));
    assert_eq!(titles(&a), ["mail", "second"]);
    assert!(a.is_dirty());
    a.save().unwrap();
    let disk = on_disk(&path).unlock(&pw()).unwrap();
    assert_eq!(disk.items().count(), 2);
}

#[test]
fn key_mismatch_then_lock_preserves_a_clean_vault() {
    let (_dir, path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    b.edit(|v| v.rotate_vault_key(&pw(), wall_ms()))
        .unwrap()
        .unwrap();
    b.save().unwrap();
    let rotated = fs::read(&path).unwrap();
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::KeyRotatedOnDisk)
    }));
    assert!(!a.is_dirty());

    let _ = a.lock();
    ea.pump();
    let unsaved = a
        .backups()
        .unwrap()
        .into_iter()
        .find(|i| i.kind == BackupKind::Unsaved)
        .expect("unsaved snapshot on lock");
    assert!(ea.any(|e| *e == SyncEvent::BackupTaken(unsaved.path.clone())));
    let kept = LockedVault::parse(&fs::read(&unsaved.path).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert_eq!(kept.items().count(), 1);
    assert_eq!(fs::read(&path).unwrap(), rotated);
}

#[test]
fn foreign_sibling_is_reported_once_per_content() {
    let (dir, _path, mut a, _b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let foreign = |seed: u128| {
        vault_core::UnlockedVault::create(&pw(), KdfParams::for_tests(), Uuid::from_u128(seed))
            .serialize()
    };
    let planted = dir.path().join("other.vault");
    let first = foreign(1);
    plant_package(&planted, &first);
    let is_foreign = |e: &SyncEvent| *e == SyncEvent::ForeignVault;
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.count(is_foreign) == 1
    }));

    // Same bytes again (new package, new events): not reported again.
    plant_package(&planted, &first);
    let drained = drain_for(&mut a, 5);
    ea.pump();
    assert!(drained > 0, "rewrite produced no watcher signal");
    assert_eq!(ea.count(is_foreign), 1);

    // Different content: reported again.
    plant_package(&planted, &foreign(2));
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.count(is_foreign) == 2
    }));
}

#[test]
fn foreign_primary_then_clean_lock_preserves_our_state() {
    let (_dir, path, mut a, _b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let foreign =
        vault_core::UnlockedVault::create(&pw(), KdfParams::for_tests(), DEV_B).serialize();
    plant(&path, &foreign);
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::ForeignVault)
    }));
    assert!(!a.is_dirty());

    // Clean, but our last saved state is no longer on disk: lock still preserves it.
    let _ = a.lock();
    ea.pump();
    let unsaved = a
        .backups()
        .unwrap()
        .into_iter()
        .find(|i| i.kind == BackupKind::Unsaved)
        .expect("unsaved snapshot on lock");
    assert!(ea.any(|e| *e == SyncEvent::BackupTaken(unsaved.path.clone())));
    let kept = LockedVault::parse(&fs::read(&unsaved.path).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert_eq!(kept.items().next().unwrap().title, "mail");
    assert_eq!(fs::read(&path).unwrap(), foreign);
}

#[test]
fn tampered_primary_then_lock_without_save_is_rewritten_after_unlock() {
    let (_dir, path, mut a, _b, _id) = two_devices();
    a.edit(|v| v.insert(Item::new("second", Uuid::nil(), T0), T0))
        .unwrap();
    a.save().unwrap();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let mut file = VaultFile::parse(&fs::read(&path).unwrap()).unwrap();
    file.items[1].ct[0] ^= 0x01;
    let tampered = file.to_bytes();
    plant(&path, &tampered);
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::CorruptOnDisk)
    }));

    let _ = a.lock();
    a.unlock(&pw()).unwrap();
    assert!(a.is_dirty(), "rewrite was forgotten across lock");
    assert_eq!(titles(&a), ["mail", "second"]);
    // And once more across another lock without saving.
    let _ = a.lock();
    a.unlock(&pw()).unwrap();
    assert!(a.is_dirty());
    a.save().unwrap();
    assert_ne!(fs::read(&path).unwrap(), tampered);
    assert_eq!(on_disk(&path).unlock(&pw()).unwrap().items().count(), 2);
}

#[test]
fn restore_while_locked_absorbs_queued_conflicts() {
    let (dir, _path, mut a, mut b, _id) = two_devices();
    let snap = a.backups().unwrap()[0].path.clone();
    let _ = a.lock();
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = dir.path().join("test 2.vault");
    plant_package(&copy, &b.vault().unwrap().serialize());
    a.start_watching().unwrap();
    assert!(wait_until(|| a.poll() > 0));
    assert!(copy.exists(), "absorbed while locked");

    let mut ea = Events::new(&a);
    a.restore_from(&snap, &pw()).unwrap();
    ea.pump();
    assert!(ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_))));
    assert!(!copy.exists());
    assert!(titles(&a).contains(&"from b".to_owned()));
}

/// Only `vault.bin` and sibling packages matter: writes under `attachments/` and `backups/`,
/// tmp files in the package, and a sibling `*.vault` that is a plain file (the old layout)
/// produce nothing.
#[test]
fn watcher_ignores_attachments_backups_and_non_package_siblings() {
    let (dir, path, mut a, mut b, _id) = two_devices();
    let package = path.parent().unwrap().to_owned();
    let attachments = package.join("attachments");
    fs::create_dir_all(&attachments).unwrap();
    let backups = package.join("backups");
    a.start_watching().unwrap();
    // Let anything from setup settle.
    drain_for(&mut a, 3);
    let mut ea = Events::new(&a);

    plant(
        &attachments.join("00000000000000000000000000000001.bin"),
        b"blob",
    );
    // A provider's conflicted copy of a blob is not a vault-file conflict.
    plant(
        &attachments.join("00000000000000000000000000000001 (Mac's conflicted copy).bin"),
        &b.vault().unwrap().serialize(),
    );
    plant(
        &attachments.join("vault 2.bin"),
        &b.vault().unwrap().serialize(),
    );
    plant(
        &backups.join("test-2020-01-01T00-00-00Z.vault.bin"),
        b"snap",
    );
    fs::create_dir(backups.join("conflict-2020-01-01T00-00-00Z-test 2.vault")).unwrap();
    fs::write(package.join(".vault.bin.tmp-0011aabb"), b"tmp").unwrap();
    assert_eq!(
        drain_for(&mut a, 5),
        0,
        "events inside the package were not ignored"
    );

    // A sibling `.vault` file is a candidate name but not a package: never absorbed.
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let file_copy = dir.path().join("test 2.vault");
    plant(&file_copy, &b.vault().unwrap().serialize());
    assert!(drain_for(&mut a, 5) > 0, "sibling produced no signal");
    ea.pump();
    assert!(file_copy.is_file());
    assert!(!ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_) | SyncEvent::Merged(_))));
    assert_eq!(titles(&a), ["mail"]);

    // Positive control: the primary itself is still watched.
    plant(&path, &b.vault().unwrap().serialize());
    assert!(wait_until(|| {
        a.poll();
        titles(&a) == ["from b", "mail"]
    }));
}

/// A provider may create the package directory before `vault.bin` arrives inside it: the
/// arrival is its own event, and the package is absorbed then.
#[test]
fn conflict_package_whose_vault_file_arrives_late_is_absorbed() {
    let (dir, _path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let copy = dir.path().join("test 2.vault");
    fs::create_dir(&copy).unwrap();
    assert!(wait_until(|| a.poll() > 0));
    drain_for(&mut a, 2);
    assert!(copy.exists());

    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    plant(&copy.join(VAULT_FILE_NAME), &b.vault().unwrap().serialize());
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_)))
    }));
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!copy.exists());
}

/// B's unsaved state (one extra item) written as a per-file conflicted copy of `vault.bin`
/// named `name` inside the package (Dropbox, Google Drive, Syncthing); A absorbs it.
fn absorb_inner_file(name: &str) {
    let (_dir, path, mut a, mut b, _id) = two_devices();
    let package = path.parent().unwrap().to_owned();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = package.join(name);
    plant(&copy, &b.vault().unwrap().serialize());

    assert!(
        wait_until(|| {
            a.poll();
            ea.pump();
            ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_)))
        }),
        "{name} not absorbed"
    );
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!copy.exists());
    let moved = ea
        .seen
        .iter()
        .find_map(|e| match e {
            SyncEvent::ConflictAbsorbed(p) => Some(p.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(moved.parent().unwrap(), package.join("backups"));
    let stem = name.strip_suffix(".bin").unwrap();
    let moved_name = moved.file_name().unwrap().to_str().unwrap();
    assert!(moved_name.starts_with("conflict-"), "{moved_name}");
    assert!(
        moved_name.ends_with(&format!("-{stem}.vault.bin")),
        "{moved_name}"
    );
    assert!(moved.is_file());
    let listed = a.backups().unwrap();
    assert!(listed.iter().any(|i| i.path == moved && i.is_conflict()));
    assert_eq!(on_disk(&path).unlock(&pw()).unwrap().items().count(), 2);
    // The moved copy restores like a snapshot.
    a.restore_from(&moved, &pw()).unwrap();
    assert_eq!(titles(&a), ["from b", "mail"]);
}

#[test]
fn dropbox_per_file_conflicted_copy_is_absorbed() {
    absorb_inner_file("vault (Chris's conflicted copy 2026-10-30).bin");
}

#[test]
fn numbered_per_file_copy_is_absorbed() {
    absorb_inner_file("vault 2.bin");
}

#[test]
fn per_file_copy_seen_while_locked_is_absorbed_on_unlock() {
    let (_dir, path, mut a, mut b, _id) = two_devices();
    let _ = a.lock();
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = path.parent().unwrap().join("vault 2.bin");
    plant(&copy, &b.vault().unwrap().serialize());
    // Existing per-file copies are queued by the start-up scan.
    a.start_watching().unwrap();
    assert!(wait_until(|| a.poll() > 0));
    assert!(copy.exists());
    a.unlock(&pw()).unwrap();
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!copy.exists());
}

/// Opening through a symlink resolves it: the watcher observes the real parent directory.
#[test]
fn symlinked_package_is_resolved_and_watched() {
    let (_dir, path, _a, mut b, _id) = two_devices();
    let real = path.parent().unwrap().to_owned();
    let links = tempfile::tempdir().unwrap();
    let link = links.path().join("link.vault");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut c = SyncedVault::open(&link, Uuid::from_u128(0xC), Arc::new(NoopHooks)).unwrap();
    assert_eq!(c.path(), fs::canonicalize(&real).unwrap());
    c.unlock(&pw()).unwrap();
    c.start_watching().unwrap();
    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    b.save().unwrap();
    assert!(wait_until(|| {
        c.poll();
        titles(&c) == ["from b", "mail"]
    }));
}

/// Another device changed the password and then rotated the key: the password slots were
/// replaced (new ids, new KDF salt), so this is reported as `KeyMismatch`, not as a rotation.
/// The new password re-opens and merges.
#[test]
fn password_change_with_rotation_elsewhere_reports_key_mismatch() {
    let (_dir, path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let new_pw = secret("a brand new password");
    b.edit(|v| {
        v.change_password(&pw(), &new_pw, KdfParams::for_tests(), wall_ms())
            .unwrap();
        v.rotate_vault_key(&new_pw, wall_ms()).unwrap();
        v.insert(Item::new("from b", Uuid::nil(), T0), T0)
    })
    .unwrap();
    b.save().unwrap();
    let written = fs::read(&path).unwrap();

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::KeyMismatch)
    }));
    assert!(!ea.any(|e| *e == SyncEvent::KeyRotatedOnDisk));
    assert!(matches!(a.save(), Err(SyncError::KeyMismatch)));
    assert_eq!(fs::read(&path).unwrap(), written);
    assert!(a.unlock(&pw()).is_err());
    a.unlock(&new_pw).unwrap();
    assert_eq!(titles(&a), ["from b", "mail"]);
}

/// A tampered first item record fails with the cached key exactly like a key change, but the
/// slots are unchanged: identical slots cannot wrap another key, so it is not a rotation.
#[test]
fn tampered_first_record_with_unchanged_slots_is_not_a_rotation() {
    let (_dir, path, mut a, _b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let mut file = VaultFile::parse(&fs::read(&path).unwrap()).unwrap();
    file.items[0].ct[0] ^= 0x01;
    plant(&path, &file.to_bytes());

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::KeyMismatch)
    }));
    assert!(!ea.any(|e| *e == SyncEvent::KeyRotatedOnDisk));
    // The password unlock tells tampering apart and keeps ours.
    a.unlock(&pw()).unwrap();
    ea.pump();
    assert!(ea.any(|e| *e == SyncEvent::CorruptOnDisk));
    assert_eq!(titles(&a), ["mail"]);
}

/// A flipped nonce in our password slot on disk. The header is bound into the manifest digest
/// (core stamps every vault at creation), so opening the file with the cached key fails as
/// tampering: `CorruptOnDisk`, never a key event, the in-memory vault is kept and nothing is
/// adopted. The vault is marked dirty, and the next save writes our intact slots back so the
/// password opens the file again.
#[test]
fn flipped_slot_nonce_is_detected_as_tamper() {
    let (_dir, path, mut a, _b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    let mut file = VaultFile::parse(&fs::read(&path).unwrap()).unwrap();
    match &mut file.header.slots[0] {
        vault_core::Slot::Key(k) => k.nonce[0] ^= 0x01,
        vault_core::Slot::Opaque(_) => unreachable!("create makes a password slot"),
    }
    let tampered = file.to_bytes();
    plant(&path, &tampered);

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::CorruptOnDisk)
    }));
    assert!(!ea.any(|e| matches!(
        e,
        SyncEvent::KeyMismatch | SyncEvent::KeyRotatedOnDisk | SyncEvent::Merged(_)
    )));
    // In-memory kept, nothing adopted, disk untouched until the rewrite.
    assert_eq!(titles(&a), ["mail"]);
    assert!(a.is_dirty());
    assert_eq!(fs::read(&path).unwrap(), tampered);

    // The next save repairs the file: the password opens it again.
    a.edit(|v| v.insert(Item::new("from a", Uuid::nil(), T0), T0))
        .unwrap();
    a.save().unwrap();
    let disk = LockedVault::parse(&fs::read(&path).unwrap())
        .unwrap()
        .unlock(&pw())
        .unwrap();
    assert_eq!(disk.items().count(), 2);
    let _ = a.lock();
    a.unlock(&pw()).unwrap();
    assert_eq!(titles(&a), ["from a", "mail"]);
}

/// `Ärzte` with Ä precomposed (NFC, as the app writes it) and decomposed (NFD, as some
/// providers deliver names).
const NFC_NAME: &str = "\u{c4}rzte.vault";
const NFD_STEM: &str = "A\u{308}rzte";

/// A creates `Ärzte.vault` (NFC) with one item; B opens the same package through the NFD
/// spelling of its path (a provider-delivered path), so every event B's watcher sees names
/// the package in a different form than B was given.
///
/// On APFS these end-to-end tests also pass without NFC matching (`canonicalize` and FSEvents
/// both return the stored form); the discriminating checks are the classifier unit tests in
/// `src/watch.rs`, which feed NFD event paths directly. These guard the whole pipeline.
fn nfc_package_opened_as_nfd() -> (TempDir, PathBuf, SyncedVault, SyncedVault) {
    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join(NFC_NAME);
    let mut a = SyncedVault::create(
        &package,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        Arc::new(NoopHooks),
    )
    .unwrap();
    a.edit(|v| v.insert(Item::new("mail", Uuid::nil(), T0), T0))
        .unwrap();
    a.save().unwrap();
    let nfd = dir.path().join(format!("{NFD_STEM}.vault"));
    let mut b = SyncedVault::open(&nfd, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    (dir, package, a, b)
}

/// Writes to the NFC-named package reach B (opened via NFD) as primary changes: merged, and
/// B's own package is never mistaken for a conflicted sibling (which would move it away).
#[test]
fn package_named_in_another_normalisation_form_is_still_primary() {
    let (dir, package, mut a, mut b) = nfc_package_opened_as_nfd();
    b.start_watching().unwrap();
    let mut eb = Events::new(&b);
    a.edit(|v| v.insert(Item::new("from a", Uuid::nil(), T0), T0))
        .unwrap();
    a.save().unwrap();
    assert!(wait_until(|| {
        b.poll();
        titles(&b) == ["from a", "mail"]
    }));
    drain_for(&mut b, 2);
    eb.pump();
    assert!(eb.any(merged));
    assert!(
        !eb.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_))),
        "{:?}",
        eb.seen
    );
    assert!(package.join(VAULT_FILE_NAME).is_file());
    // Nothing was renamed on disk: the package keeps its NFC name.
    let names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, [NFC_NAME]);
}

/// A numbered sibling whose name arrives in NFD next to the NFC package is absorbed; an
/// unrelated vault whose name differs by more than normalisation is left alone.
#[test]
fn sibling_in_another_normalisation_form_is_absorbed() {
    let (dir, package, mut a, mut b) = nfc_package_opened_as_nfd();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);

    // Another vault, named `Arzte 2.vault`: a candidate only by the generic rule, rejected
    // by its vault id.
    let other_pkg = dir.path().join(".other.vault");
    let other = SyncedVault::create(
        &other_pkg,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        Arc::new(NoopHooks),
    )
    .unwrap();
    drop(other);
    let unrelated = dir.path().join("Arzte 2.vault");
    fs::rename(&other_pkg, &unrelated).unwrap();

    b.edit(|v| v.insert(Item::new("from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = dir.path().join(format!("{NFD_STEM} 2.vault"));
    plant_package(&copy, &b.vault().unwrap().serialize());
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| matches!(e, SyncEvent::ConflictAbsorbed(_)))
    }));
    assert_eq!(titles(&a), ["from b", "mail"]);
    assert!(!copy.exists());
    let moved = a
        .backups()
        .unwrap()
        .into_iter()
        .find(|i| i.is_conflict())
        .unwrap();
    assert!(moved.path.starts_with(package.join("backups")));
    drain_for(&mut a, 2);
    ea.pump();
    assert!(
        unrelated.join(VAULT_FILE_NAME).is_file(),
        "unrelated vault moved"
    );
    assert_eq!(ea.count(|e| matches!(e, SyncEvent::ConflictAbsorbed(_))), 1);
}
