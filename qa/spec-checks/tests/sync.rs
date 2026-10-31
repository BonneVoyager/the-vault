//! vault-sync (03-sync.md) with two handles on one folder, conflict copies of both shapes,
//! backups, attachments. Uses NoopHooks (03 §9 "default CloudHooks").
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use spec_checks::*;
use std::path::Path;
use vault_core::*;

fn val(v: &UnlockedVault, id: uuid::Uuid, name: &str) -> Option<String> {
    v.get(id)?.fields.iter().find(|f| f.name == name).map(|f| f.value.expose_secret().clone())
}
fn backups_dir(pkg: &Path) -> std::path::PathBuf {
    pkg.join("backups")
}

/// 03 §1 layout + §2 save: package dir, vault.bin parseable, tmp gone, mode 0600.
#[test]
fn s01_save_layout() {
    let d = tempdir();
    let pkg = d.path().join("Personal.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    assert!(pkg.is_dir(), "03 §1: <name>.vault is a package directory");
    let names = ls(&pkg);
    assert!(names.contains(&"vault.bin".to_string()), "{names:?}");
    assert!(!names.iter().any(|n| n.contains(".tmp")), "tmp left behind: {names:?}");
    assert_eq!(mode(&primary(&pkg)), 0o600, "vault.bin mode 0600");
    assert_eq!(read_vault(&pkg).items().count(), 1);
    assert!(!a.s.is_dirty());
    // nothing written as siblings of the package except the package itself
    assert_eq!(ls(d.path()), vec!["Personal.vault".to_string()], "no sibling files (03 §1 package replaces siblings)");
    // created_at is a real time (01 §2 "created_at: u64 unix seconds")
    let raw = split(&std::fs::read(primary(&pkg)).unwrap());
    let ca = u64_of(get(&raw.header, "created_at").unwrap());
    assert!(ca > 1_600_000_000, "header created_at = {ca}; expected unix seconds of creation");
}

/// 03 §4 policy: first save after unlock snapshots; two saves within 1 s -> one backup;
/// item-count decrease -> extra backup; snapshot = exact bytes just written; name pattern.
#[test]
fn s02_backup_policy() {
    let d = tempdir();
    let pkg = d.path().join("p.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("one", now_ms());
    a.s.save().unwrap();
    a.add_login("two", now_ms());
    a.s.save().unwrap();
    let snaps: Vec<String> = ls(&backups_dir(&pkg)).into_iter().filter(|n| n.starts_with("p-")).collect();
    assert_eq!(snaps.len(), 1, "two saves within an hour -> one snapshot: {snaps:?}");
    let name = &snaps[0];
    // p-YYYY-MM-DDTHH-MM-SSZ.vault[.bin]
    let ok = name.len() >= "p-2026-10-28T14-03-11Z.vault".len() && name.as_bytes()[12] == b'T' && name.contains('Z') && !name.contains(':');
    assert!(ok, "snapshot name {name}");
    // exact bytes: the newest snapshot equals the bytes written at that save -> must open
    let sb = std::fs::read(backups_dir(&pkg).join(name)).unwrap();
    LockedVault::parse(&sb).unwrap().unlock(&pw(PW)).unwrap();
    // item count decreased -> extra snapshot
    a.s.edit(|v| v.delete(id, now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    let snaps2: Vec<String> = ls(&backups_dir(&pkg)).into_iter().filter(|n| n.starts_with("p-")).collect();
    assert!(snaps2.len() >= 2, "item count decreased -> extra backup: {snaps2:?}");
    // same-second names get a -N suffix; pick the newest by mtime
    let newest = snaps2.iter().max_by_key(|n| std::fs::metadata(backups_dir(&pkg).join(n)).unwrap().modified().unwrap()).unwrap();
    let latest = std::fs::read(backups_dir(&pkg).join(newest)).unwrap();
    assert_eq!(latest, std::fs::read(primary(&pkg)).unwrap(), "snapshot = exact bytes just written");
    // first save after unlock -> snapshot
    let _ = a.s.lock();
    a.s.unlock(&pw(PW)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    a.add_login("three", now_ms());
    a.s.save().unwrap();
    let snaps3: Vec<String> = ls(&backups_dir(&pkg)).into_iter().filter(|n| n.starts_with("p-")).collect();
    assert!(snaps3.len() > snaps2.len(), "first save after unlock -> snapshot: {snaps3:?}");
    let infos = a.s.backups().unwrap();
    assert!(infos.len() >= snaps3.len());
    // backup_now
    let p = a.s.backup_now().unwrap();
    assert!(p.exists());
}

/// 03 §9: two SyncedVaults on the same path edit different fields of one item; both converge.
#[test]
fn s03_two_handles_converge_via_watcher() {
    let d = tempdir();
    let pkg = d.path().join("w.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("shared", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    b.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.s.edit(|v| v.set_field_named(id, "username", pw("from-a"), now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    b.s.edit(|v| v.set_field_named(id, "password", pw("from-b"), now_ms())).unwrap().unwrap();
    b.s.save().unwrap();
    let ok = a.wait_for(10, |_| false) || true;
    let _ = ok;
    a.drain();
    b.drain();
    for (n, x) in [("a", &a), ("b", &b)] {
        assert_eq!(val(x.v(), id, "username").as_deref(), Some("from-a"), "{n} username; events {:?}", x.seen);
        assert_eq!(val(x.v(), id, "password").as_deref(), Some("from-b"), "{n} password; events {:?}", x.seen);
    }
    let disk = read_vault(&pkg);
    assert_eq!(val(&disk, id, "username").as_deref(), Some("from-a"));
    assert_eq!(val(&disk, id, "password").as_deref(), Some("from-b"));
    assert_eq!(snap_vault(a.v()), snap_vault(b.v()));
}

/// 03 §9: A deletes item, B edits it later -> B's edit wins; B edits earlier -> delete wins.
#[test]
fn s04_delete_vs_edit_across_handles() {
    for later_edit in [true, false] {
        let d = tempdir();
        let pkg = d.path().join("d.vault");
        let mut a = Dev::create(&pkg);
        let t0 = now_ms();
        let id = a.add_login("x", t0);
        a.s.save().unwrap();
        let mut b = Dev::open(&pkg);
        a.s.start_watching().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(700));
        let (td, te) = if later_edit { (t0 + 1_000, t0 + 2_000) } else { (t0 + 2_000, t0 + 1_000) };
        a.s.edit(|v| v.delete(id, td)).unwrap().unwrap();
        b.s.edit(|v| v.set_field_named(id, "username", pw("edited"), te)).unwrap().unwrap();
        a.s.save().unwrap();
        b.s.save().unwrap(); // pre-write merge
        a.wait_for(4, |_| false); // A learns B's write through its watcher (03 §3)
        let disk = read_vault(&pkg);
        let live = disk.items().any(|i| i.id == id);
        assert_eq!(live, later_edit, "later_edit={later_edit}");
        assert_eq!(a.v().items().any(|i| i.id == id), later_edit);
        assert_eq!(b.v().items().any(|i| i.id == id), later_edit);
    }
}

fn conflict_copy_with_extra_item(pkg: &Path, dir: &Path, name: &str) -> (std::path::PathBuf, uuid::Uuid) {
    // Make a whole-package copy (iCloud shape) that has one more item than the primary.
    let copy = dir.join(name);
    copy_dir(pkg, &copy);
    let mut c = Dev::open(&copy);
    let id = c.add_login("from-conflict", now_ms());
    c.s.save().unwrap();
    drop(c);
    (copy, id)
}

/// 03 §6 whole-package conflict copy (iCloud): absorbed, merged, moved to backups/conflict-*.
#[test]
fn s05_sibling_package_conflict_absorbed() {
    for name in ["s 2.vault", "s (Mac's conflicted copy 2026-10-30).vault", "S 3.VAULT"] {
        let d = tempdir();
        let pkg = d.path().join("s.vault");
        let mut a = Dev::create(&pkg);
        a.add_login("base", now_ms());
        a.s.save().unwrap();
        let tmpd = tempdir();
        let (made, cid) = conflict_copy_with_extra_item(&pkg, tmpd.path(), "staging.vault");
        a.s.start_watching().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(700));
        let target = d.path().join(name);
        std::fs::rename(&made, &target).unwrap();
        let got = a.wait_for(10, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
        assert!(got, "{name}: no ConflictAbsorbed; events {:?}", a.seen);
        assert!(a.v().get(cid).is_some(), "{name}: conflict item merged");
        assert!(read_vault(&pkg).get(cid).is_some(), "{name}: merged result saved");
        assert!(!target.exists(), "{name}: conflict package moved away");
        let moved: Vec<String> = ls(&backups_dir(&pkg)).into_iter().filter(|n| n.starts_with("conflict-")).collect();
        assert_eq!(moved.len(), 1, "{name}: {moved:?}");
        assert!(moved[0].ends_with(name), "{name}: moved name keeps original: {moved:?}");
        assert!(backups_dir(&pkg).join(&moved[0]).join("vault.bin").exists(), "never delete a conflict copy");
    }
}

/// 03 §6 per-file conflict copy (Dropbox/Google Drive/Syncthing): `vault*.bin` inside the package.
#[test]
fn s06_in_package_conflict_absorbed() {
    for name in ["vault (Mac's conflicted copy 2026-10-30).bin", "vault 2.bin", "VAULT 3.BIN", "vault (1).bin"] {
        let d = tempdir();
        let pkg = d.path().join("q.vault");
        let mut a = Dev::create(&pkg);
        a.add_login("base", now_ms());
        a.s.save().unwrap();
        let tmpd = tempdir();
        let (made, cid) = conflict_copy_with_extra_item(&pkg, tmpd.path(), "staging.vault");
        a.s.start_watching().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(700));
        let target = pkg.join(name);
        std::fs::copy(made.join("vault.bin"), &target).unwrap();
        let got = a.wait_for(10, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
        if name == "vault (1).bin" {
            // not one of the spec'd patterns; whatever happens, the file must not be deleted
            assert!(target.exists() || ls(&backups_dir(&pkg)).iter().any(|n| n.contains("vault (1)")), "{name} vanished");
            continue;
        }
        assert!(got, "{name}: no ConflictAbsorbed; events {:?}", a.seen);
        assert!(a.v().get(cid).is_some(), "{name}: merged");
        assert!(!target.exists(), "{name}: moved");
        let moved: Vec<String> = ls(&backups_dir(&pkg)).into_iter().filter(|n| n.starts_with("conflict-")).collect();
        assert_eq!(moved.len(), 1, "{name}: {moved:?}");
        assert!(moved[0].ends_with(".vault.bin"), "per-file -> conflict-<ts>-<orig>.vault.bin: {moved:?}");
    }
}

/// 03 §6 step 1 / §9: a conflict-shaped copy with a different vault_id is ignored and untouched.
#[test]
fn s07_foreign_conflict_copy_untouched() {
    let d = tempdir();
    let pkg = d.path().join("f.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("base", now_ms());
    a.s.save().unwrap();
    let other = tempdir();
    let opkg = other.path().join("f.vault");
    let mut o = Dev::create(&opkg);
    o.add_login("foreign", now_ms());
    o.s.save().unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let sib = d.path().join("f 2.vault");
    copy_dir(&opkg, &sib);
    let inpkg = pkg.join("vault 2.bin");
    std::fs::copy(opkg.join("vault.bin"), &inpkg).unwrap();
    a.wait_for(4, |_| false);
    assert!(sib.join("vault.bin").exists(), "foreign sibling untouched");
    assert!(inpkg.exists(), "foreign in-package copy untouched");
    assert_eq!(a.v().items().count(), 1);
    assert!(!a.seen.iter().any(|e| e.starts_with("ConflictAbsorbed")), "{:?}", a.seen);
}

/// 03 §3 step 3 + §9: corrupt primary -> CorruptOnDisk, memory intact, next save rewrites valid file.
#[test]
fn s08_corrupt_primary() {
    let d = tempdir();
    let pkg = d.path().join("c.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("keep", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let good = std::fs::read(primary(&pkg)).unwrap();
    std::fs::write(primary(&pkg), &good[..good.len() / 2]).unwrap(); // truncated, version bytes intact
    let got = a.wait_for(8, |e| e.iter().any(|x| x.contains("CorruptOnDisk")));
    assert!(got, "CorruptOnDisk; events {:?}", a.seen);
    assert!(a.v().get(id).is_some(), "in-memory intact");
    a.s.edit(|v| v.set_field_named(id, "username", pw("after"), now_ms())).unwrap().unwrap();
    let r = a.s.save();
    assert!(r.is_ok(), "next save rewrites a valid file: {r:?}");
    assert_eq!(val(&read_vault(&pkg), id, "username").as_deref(), Some("after"));
}

/// 03 §3: newer FORMAT_VERSION or foreign vault_id on disk -> save refused, in-memory kept, file untouched.
#[test]
fn s09_save_blocked() {
    let d = tempdir();
    let pkg = d.path().join("n.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("x", now_ms());
    a.s.save().unwrap();
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&3u16.to_be_bytes());
    std::fs::write(primary(&pkg), &b).unwrap();
    a.s.edit(|v| v.set_field_named(id, "username", pw("blocked"), now_ms())).unwrap().unwrap();
    let r = a.s.save();
    assert!(r.is_err(), "newer version on disk -> save refused");
    assert_eq!(std::fs::read(primary(&pkg)).unwrap(), b, "file untouched");
    assert_eq!(val(a.v(), id, "username").as_deref(), Some("blocked"), "in-memory kept");
    // foreign vault at the primary path
    let other = tempdir();
    let opkg = other.path().join("o.vault");
    let mut o = Dev::create(&opkg);
    o.s.save().unwrap();
    let ob = std::fs::read(primary(&opkg)).unwrap();
    std::fs::write(primary(&pkg), &ob).unwrap();
    let r = a.s.save();
    assert!(r.is_err(), "foreign vault on disk -> save refused");
    assert_eq!(std::fs::read(primary(&pkg)).unwrap(), ob);
}

/// 03 §3 "the save is refused with SyncEvent::SaveBlocked{NewerVersion | ForeignVault}"; 03 §8 lists
/// SaveBlocked(SaveBlockReason) among SyncEvent variants. A subscriber must be able to tell this
/// apart from a generic error.
#[test]
fn s09b_save_blocked_is_an_event() {
    let d = tempdir();
    let pkg = d.path().join("sb.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("x", now_ms());
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&3u16.to_be_bytes());
    std::fs::write(primary(&pkg), &b).unwrap();
    a.wait_for(4, |_| false);
    a.s.edit(|v| v.set_field_named(id, "username", pw("x2"), now_ms())).unwrap().unwrap();
    let r = a.s.save();
    a.drain();
    assert!(
        a.seen.iter().any(|e| e.starts_with("SaveBlocked")),
        "no SaveBlocked event; save -> {r:?}; events {:?}",
        a.seen
    );
}

/// 03 §8 lock(): unsaved edits are snapshotted to a backup first (kind Unsaved), never pruned.
#[test]
fn s10_lock_with_unsaved_edits() {
    let d = tempdir();
    let pkg = d.path().join("l.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    // make the primary unwritable for this handle by planting a newer version so save is blocked,
    // then lock: unsaved edit must land in a backup.
    let id = a.add_login("unsaved-item", now_ms());
    let mut b = std::fs::read(primary(&pkg)).unwrap();
    b[4..6].copy_from_slice(&3u16.to_be_bytes());
    std::fs::write(primary(&pkg), &b).unwrap();
    let _ = a.s.lock();
    assert!(a.s.vault().is_none());
    let mut found = false;
    for e in std::fs::read_dir(backups_dir(&pkg)).unwrap() {
        let p = e.unwrap().path();
        if let Ok(bytes) = std::fs::read(&p) {
            if let Ok(u) = LockedVault::parse(&bytes).and_then(|l| l.unlock(&pw(PW))) {
                found |= u.get(id).is_some();
            }
        }
    }
    assert!(found, "unsaved edit preserved in a backup on lock; backups {:?}", ls(&backups_dir(&pkg)));
}

/// 03 §8 restore_from: snapshots current first; works when the primary no longer parses.
#[test]
fn s11_restore_from() {
    let d = tempdir();
    let pkg = d.path().join("r.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("v1", now_ms());
    a.s.save().unwrap();
    let snap = a.s.backup_now().unwrap();
    a.s.edit(|v| v.delete(id, now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    std::fs::write(primary(&pkg), b"not a vault").unwrap();
    let before: Vec<String> = ls(&backups_dir(&pkg));
    a.s.restore_from(&snap, &pw(PW)).expect("restore works when primary does not parse");
    let after: Vec<String> = ls(&backups_dir(&pkg));
    assert!(after.len() > before.len(), "current snapshotted first: {before:?} -> {after:?}");
    assert!(read_vault(&pkg).items().any(|i| i.id == id), "restored content on disk");
    // the snapshot of the unparsable current file must preserve its bytes
    let preserved = after.iter().filter(|n| !before.contains(n)).any(|n| std::fs::read(backups_dir(&pkg).join(n)).map(|b| b == b"not a vault").unwrap_or(false));
    assert!(preserved, "unparsable current preserved before restore");
    // wrong password refused
    assert!(a.s.restore_from(&snap, &pw("wrong")).is_err());
}

/// 03 §2 V-02: two handles writing concurrently do not lose items (flock around read-merge-write).
#[test]
fn s12_concurrent_writers_no_lost_items() {
    let d = tempdir();
    let pkg = d.path().join("cc.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    let p1 = pkg.clone();
    let p2 = pkg.clone();
    let t = |p: std::path::PathBuf, tag: &'static str| {
        std::thread::spawn(move || {
            let mut h = Dev::open(&p);
            for i in 0..15 {
                h.add_login(&format!("{tag}{i}"), now_ms());
                h.s.save().unwrap();
            }
        })
    };
    let h1 = t(p1, "a");
    let h2 = t(p2, "b");
    h1.join().unwrap();
    h2.join().unwrap();
    let n = read_vault(&pkg).items().count();
    assert_eq!(n, 30, "items on disk after concurrent writers");
}

/// 03 §3 step 5: locked handle sees ChangedWhileLocked; next unlock reads the on-disk version.
#[test]
fn s13_changed_while_locked() {
    let d = tempdir();
    let pkg = d.path().join("cl.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    let _ = a.s.lock();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let mut b = Dev::open(&pkg);
    let id = b.add_login("while-locked", now_ms());
    b.s.save().unwrap();
    let got = a.wait_for(8, |e| e.iter().any(|x| x.contains("ChangedWhileLocked")));
    assert!(got, "ChangedWhileLocked; {:?}", a.seen);
    a.s.unlock(&pw(PW)).unwrap();
    assert!(a.v().get(id).is_some());
}

/// 03 §5 V-01 via the sync layer: B changes the password; A (unlocked, watching, with an unsaved
/// edit) merges and saves; the file opens with the new password only and keeps A's edit.
#[test]
fn s14_password_change_on_other_handle_survives() {
    let d = tempdir();
    let pkg = d.path().join("pc.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("x", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.s.edit(|v| v.set_field_named(id, "username", pw("a-unsaved"), now_ms())).unwrap().unwrap();
    b.s.edit(|v| v.change_password(&pw(PW), &pw("brand new pass"), KdfParams::for_tests(), now_ms())).unwrap().unwrap();
    b.s.save().unwrap();
    a.wait_for(5, |e| e.iter().any(|x| x.starts_with("Merged") || x.contains("Key")));
    a.s.save().unwrap();
    let l = LockedVault::parse(&std::fs::read(primary(&pkg)).unwrap()).unwrap();
    let u = l.unlock(&pw("brand new pass")).expect("new password opens after A's save");
    assert_eq!(val(&u, id, "username").as_deref(), Some("a-unsaved"));
    assert!(l.unlock(&pw(PW)).is_err(), "old password no longer opens");
}

/// 03 §8 / §5: key rotated on another handle -> KeyRotatedOnDisk on ours; our edits kept;
/// nothing clobbers the rotated file.
#[test]
fn s15_key_rotated_elsewhere() {
    let d = tempdir();
    let pkg = d.path().join("kr.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("x", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    b.s.edit(|v| v.rotate_vault_key(&pw(PW), now_ms())).unwrap().unwrap();
    b.s.save().unwrap();
    let rotated = std::fs::read(primary(&pkg)).unwrap();
    a.wait_for(5, |e| e.iter().any(|x| x.contains("Key")));
    a.s.edit(|v| v.set_field_named(id, "username", pw("mine"), now_ms())).unwrap().ok();
    let _ = a.s.save();
    let now = std::fs::read(primary(&pkg)).unwrap();
    let u = LockedVault::parse(&now).unwrap().unlock(&pw(PW)).unwrap();
    assert_eq!(
        indep::open_file(&now, PW).vault_key,
        indep::open_file(&rotated, PW).vault_key,
        "A must not write its old key back over the rotation"
    );
    let _ = u;
}

/// 03 §8 SyncEvent::KeyRotatedOnDisk "vault_key rotated elsewhere"; 03 §5 "a key rotation is
/// detected as before (KeyRotatedOnDisk)". KeyMismatch is documented for a password change, which
/// no longer changes the vault key.
#[test]
fn s15b_key_rotation_event_kind() {
    let d = tempdir();
    let pkg = d.path().join("kr2.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    b.s.edit(|v| v.rotate_vault_key(&pw(PW), now_ms())).unwrap().unwrap();
    b.s.save().unwrap();
    let got = a.wait_for(8, |e| e.iter().any(|x| x.contains("KeyRotatedOnDisk")));
    assert!(got, "expected KeyRotatedOnDisk; got {:?}", a.seen);
}

/// Rotation flow: KeyRotatedOnDisk on detection (03 §8), save refused, then unlock(password)
/// adopts the rotated vault, emits KeyRotatedOnDisk + Merged, and keeps our unsaved edit.
#[test]
fn s15c_key_rotation_documented_two_step_flow() {
    let d = tempdir();
    let pkg = d.path().join("kr3.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("x", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    b.s.edit(|v| v.rotate_vault_key(&pw(PW), now_ms())).unwrap().unwrap();
    let bid = b.add_login("from-b", now_ms());
    b.s.save().unwrap();
    // 03 §8: rotation elsewhere -> KeyRotatedOnDisk at detection (was KeyMismatch before the L3 fix)
    assert!(a.wait_for(8, |e| e.iter().any(|x| x.contains("KeyRotatedOnDisk") || x.contains("KeyMismatch"))), "{:?}", a.seen);
    a.s.edit(|v| v.set_field_named(id, "username", pw("a-edit"), now_ms())).unwrap().unwrap();
    assert!(a.s.save().is_err(), "save refused while key mismatched");
    a.s.unlock(&pw(PW)).unwrap();
    a.drain();
    assert!(a.seen.iter().any(|x| x.contains("KeyRotatedOnDisk")), "{:?}", a.seen);
    assert!(a.seen.iter().any(|x| x.starts_with("Merged")), "re-unlock merges on-disk items: {:?}", a.seen);
    assert!(a.v().get(bid).is_some());
    assert_eq!(val(a.v(), id, "username").as_deref(), Some("a-edit"));
    a.s.save().unwrap();
    let disk = read_vault(&pkg);
    assert_eq!(val(&disk, id, "username").as_deref(), Some("a-edit"));
    assert!(disk.get(bid).is_some());
}

/// 03 §3 step 1-2: our own write echoing back is ignored (no Merged/Corrupt events from it).
#[test]
fn s16_echo_suppressed() {
    let d = tempdir();
    let pkg = d.path().join("e.vault");
    let mut a = Dev::create(&pkg);
    a.s.save().unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    for i in 0..3 {
        a.add_login(&format!("i{i}"), now_ms());
        a.s.save().unwrap();
    }
    a.wait_for(3, |_| false);
    assert!(!a.seen.iter().any(|e| e.starts_with("Merged") || e.contains("Corrupt") || e.contains("Error")), "{:?}", a.seen);
    assert!(!a.s.is_dirty());
}
