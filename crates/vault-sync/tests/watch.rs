//! Watcher-driven reconciliation (03 §3, §6, §9): two instances on one path, conflicted copies,
//! corruption, changes while locked, key rotation by another device.
//!
//! Flakiness guards: every wait is a deadline loop around `poll()` (never a bare sleep for a
//! positive assertion); planted files are written to a hidden tmp name and renamed in, so the
//! watcher never sees a half-written `.vault`; the only fixed wait is the negative "no echo"
//! check, which waits several debounce windows.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use tempfile::TempDir;
use vault_core::format::VaultFile;
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, ItemKind, KdfParams, LockedVault, SecretString, Uuid,
};
use vault_sync::{BackupKind, DEBOUNCE, NoopHooks, SaveBlocked, SyncError, SyncEvent, SyncedVault};

const T0: u64 = 1_700_000_000_000;
const DEADLINE: Duration = Duration::from_secs(20);

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
/// and unlocks it. Neither is watching yet.
fn two_devices() -> (TempDir, PathBuf, SyncedVault, SyncedVault, Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let mut a = SyncedVault::create(
        &path,
        &pw(),
        KdfParams::for_tests(),
        DEV_A,
        Arc::new(NoopHooks),
    )
    .unwrap();
    let id = a
        .edit(|v| {
            let mut item = Item::new(ItemKind::Login, "mail", Uuid::nil(), T0);
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
    let mut b = SyncedVault::open(&path, DEV_B, Arc::new(NoopHooks)).unwrap();
    b.unlock(&pw()).unwrap();
    (dir, path, a, b, id)
}

fn field(v: &SyncedVault, id: Uuid, name: &str) -> Option<String> {
    let item = v.vault()?.get(id)?;
    if item.is_deleted() {
        return None;
    }
    Some(item.field(name)?.value.expose_secret().clone())
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

    a.edit(|v| v.set_field(id, "username", secret("alice@a"), T0 + 1_000))
        .unwrap()
        .unwrap();
    a.save().unwrap();
    b.edit(|v| v.set_field(id, "password", secret("b-pass"), T0 + 2_000))
        .unwrap()
        .unwrap();
    b.save().unwrap();

    let both = |v: &SyncedVault| {
        field(v, id, "username").as_deref() == Some("alice@a")
            && field(v, id, "password").as_deref() == Some("b-pass")
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
        item.field("username").unwrap().value.expose_secret() == "alice@a"
            && item.field("password").unwrap().value.expose_secret() == "b-pass"
    }));
    ea.pump();
    eb.pump();
    assert!(ea.any(merged), "A got no Merged");
    assert!(eb.any(merged), "B got no Merged");
    assert!(!a.is_dirty() && !b.is_dirty());
}

fn delete_vs_edit(delete_at: u64, edit_at: u64) -> (SyncedVault, SyncedVault, Uuid, TempDir) {
    let (dir, _path, mut a, mut b, id) = two_devices();
    a.start_watching().unwrap();
    b.start_watching().unwrap();
    // Order of the writes on disk is fixed (A then B); the timestamps decide the winner.
    a.edit(|v| v.delete(id, delete_at)).unwrap().unwrap();
    a.save().unwrap();
    b.edit(|v| v.set_field(id, "password", secret("edited"), edit_at))
        .unwrap()
        .unwrap();
    b.save().unwrap();
    (a, b, id, dir)
}

#[test]
fn edit_after_delete_wins() {
    let (mut a, mut b, id, _dir) = delete_vs_edit(T0 + 1_000, T0 + 2_000);
    assert!(wait_until(|| {
        a.poll();
        b.poll();
        field(&a, id, "password").as_deref() == Some("edited")
            && field(&b, id, "password").as_deref() == Some("edited")
    }));
}

#[test]
fn delete_after_edit_wins() {
    let (mut a, mut b, id, _dir) = delete_vs_edit(T0 + 2_000, T0 + 1_000);
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
    a.edit(|v| v.set_field(id, "username", secret("x"), T0 + 1_000))
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

/// B's unsaved state (one extra item) written as a sibling named `name`; A absorbs it.
fn absorb_sibling(name: &str) {
    let (dir, path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    let mut ea = Events::new(&a);
    b.edit(|v| v.insert(Item::new(ItemKind::Login, "from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = dir.path().join(name);
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
    let moved_name = moved.file_name().unwrap().to_str().unwrap();
    assert!(moved_name.starts_with("conflict-"), "{moved_name}");
    assert!(moved_name.ends_with(&format!("-{name}")), "{moved_name}");
    assert_eq!(
        moved.parent().unwrap(),
        dir.path().join("test.vault.backups")
    );
    assert!(
        a.backups()
            .unwrap()
            .iter()
            .any(|i| i.path == moved && i.is_conflict())
    );
    // The merged result is on disk.
    let disk = on_disk(&path).unlock(&pw()).unwrap();
    assert_eq!(disk.items().count(), 2);
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
    let bytes = fs::read(&other_path).unwrap();
    let planted = dir.path().join("other.vault");
    plant(&planted, &bytes);

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::ForeignVault)
    }));
    assert_eq!(fs::read(&planted).unwrap(), bytes);
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
    a.lock();
    let mut ea = Events::new(&a);
    b.edit(|v| v.insert(Item::new(ItemKind::Login, "from b", Uuid::nil(), T0), T0))
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
fn key_rotation_elsewhere_reports_mismatch_and_reverify_merges() {
    let (_dir, path, mut a, mut b, _id) = two_devices();
    a.start_watching().unwrap();
    b.start_watching().unwrap();
    let mut ea = Events::new(&a);
    b.edit(|v| v.rotate_vault_key(&pw())).unwrap().unwrap();
    b.edit(|v| v.insert(Item::new(ItemKind::Login, "from b", Uuid::nil(), T0), T0))
        .unwrap();
    b.save().unwrap();
    let rotated = fs::read(&path).unwrap();

    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::KeyMismatch)
    }));
    // In-memory untouched, disk untouched, saving refused.
    assert_eq!(titles(&a), ["mail"]);
    a.edit(|v| v.insert(Item::new(ItemKind::Login, "from a", Uuid::nil(), T0), T0))
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
    a.lock();
    b.edit(|v| v.insert(Item::new(ItemKind::Login, "from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = dir.path().join("test 2.vault");
    plant(&copy, &b.vault().unwrap().serialize());

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
        ea.any(|e| matches!(e, SyncEvent::Error(_)))
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
    a.edit(|v| v.insert(Item::new(ItemKind::Login, "second", Uuid::nil(), T0), T0))
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
    b.edit(|v| v.rotate_vault_key(&pw())).unwrap().unwrap();
    b.save().unwrap();
    let rotated = fs::read(&path).unwrap();
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.any(|e| *e == SyncEvent::KeyMismatch)
    }));
    assert!(!a.is_dirty());

    a.lock();
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
    plant(&planted, &first);
    let is_foreign = |e: &SyncEvent| *e == SyncEvent::ForeignVault;
    assert!(wait_until(|| {
        a.poll();
        ea.pump();
        ea.count(is_foreign) == 1
    }));

    // Same bytes again (new inode, new events): not reported again.
    plant(&planted, &first);
    let mut drained = 0;
    let until = Instant::now() + DEBOUNCE * 5;
    while Instant::now() < until {
        drained += a.poll();
        thread::sleep(Duration::from_millis(25));
    }
    ea.pump();
    assert!(drained > 0, "rewrite produced no watcher signal");
    assert_eq!(ea.count(is_foreign), 1);

    // Different content: reported again.
    plant(&planted, &foreign(2));
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
    a.lock();
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
    a.edit(|v| v.insert(Item::new(ItemKind::Login, "second", Uuid::nil(), T0), T0))
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

    a.lock();
    a.unlock(&pw()).unwrap();
    assert!(a.is_dirty(), "rewrite was forgotten across lock");
    assert_eq!(titles(&a), ["mail", "second"]);
    // And once more across another lock without saving.
    a.lock();
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
    a.lock();
    b.edit(|v| v.insert(Item::new(ItemKind::Login, "from b", Uuid::nil(), T0), T0))
        .unwrap();
    let copy = dir.path().join("test 2.vault");
    plant(&copy, &b.vault().unwrap().serialize());
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
