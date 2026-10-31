//! UnlockedVault::upgrade_format (01 §9, 02) and version 1 / version 2 interplay in merge and
//! sync (03 §3, §5). Added 2026-10-31.
use secrecy::{ExposeSecret, SecretVec};
use spec_checks::dev::*;
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

const FPW: &str = FIXTURE_PW;

fn slot_kinds(b: &[u8]) -> Vec<String> {
    get(&split(b).header, "slots").unwrap().as_array().unwrap().iter().map(|s| get(s, "kind").unwrap().as_text().unwrap().to_string()).collect()
}
fn field_ids(v: &UnlockedVault) -> Vec<(Uuid, Vec<Uuid>)> {
    let mut x: Vec<(Uuid, Vec<Uuid>)> = v.items_including_deleted().map(|i| (i.id, i.fields.iter().map(|f| f.id).collect())).collect();
    x.sort();
    x
}
/// v1 file with an opaque slot spliced in (unstamped base, so the splice is legitimate, see f15),
/// then unlocked, given an item and an enclave slot.
fn v1_with_extra_slots() -> (UnlockedVault, Uuid, SecretVec<u8>) {
    let raw = split(&fixture("v1-empty.vault"));
    let mut h = raw.header.clone();
    if let Some(Value::Array(s)) = get_mut(&mut h, "slots") {
        s.push(map(vec![("id", Value::Bytes(vec![0xAB; 16])), ("kind", t("hwkey")), ("zz", i(1))]));
    }
    let f = join(raw.version, &h, &raw.body);
    let mut v = LockedVault::parse(&f).unwrap().unlock(&pw(FPW)).unwrap();
    let dev = v.device_id();
    let mut it = Item::new("acct", dev, 1_000);
    it.fields.push(Field::new("password", FieldKind::Password, pw("item-secret"), 1_000));
    v.insert(it, 1_000);
    let kek = SecretVec::new(vec![7u8; 32]);
    let sid = v.add_enclave_slot(&kek, 2_000);
    (v, sid, kek)
}

/// 01 §9 "upgrade_format(password, now) moves a file to version 2 by re-wrapping the password
/// slots; it drops enclave, recovery and opaque slots (same contract as rotate_vault_key)".
#[test]
fn u01_upgrade_drops_non_password_slots() {
    let (mut v, sid, kek) = v1_with_extra_slots();
    let before = v.serialize();
    assert_eq!(version_of(&before), 1);
    let mut kinds = slot_kinds(&before);
    kinds.sort();
    assert_eq!(kinds, vec!["enclave", "hwkey", "password"]);
    let ids_before = field_ids(&v);
    let key_before = indep::open_file(&before, FPW).vault_key;
    v.upgrade_format(&pw(FPW), 5_000).unwrap();
    let after = v.serialize();
    assert_eq!(version_of(&after), 2, "upgraded file is version 2");
    assert_eq!(slot_kinds(&after), vec!["password"], "only password slots remain");
    let l = LockedVault::parse(&after).unwrap();
    let u = l.unlock(&pw(FPW)).expect("password still unlocks");
    assert!(l.unlock_with_kek(sid, &kek).is_err(), "enclave slot gone");
    assert_eq!(field_ids(&u), ids_before, "field ids (derived/explicit) unchanged by the upgrade");
    assert_eq!(snap_vault(&u), snap_vault(&v));
    let o = indep::open_file(&after, FPW);
    assert_eq!(o.vault_key, key_before, "re-wrap only: vault_key unchanged");
    for (_, _, pt) in &o.items {
        for f in get(pt, "fields").unwrap().as_array().unwrap() {
            assert!(get(f, "id").is_some(), "v2 fields carry ids");
        }
    }
    // 01 §2 slots_modified_at = "last change to slots or kdf": the upgrade changed the slots
    let sma = get(&split(&after).header, "slots_modified_at").map(u64_of);
    assert!(sma.unwrap_or(0) >= 5_000, "header stamped by the upgrade: {sma:?}");
}

/// 02 "no-op when current": on a version 2 vault nothing changes, enclave slot kept.
#[test]
fn u02_upgrade_noop_on_v2() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(FPW), KdfParams::for_tests(), dev);
    let kek = SecretVec::new(vec![3u8; 32]);
    let sid = v.add_enclave_slot(&kek, 2_000);
    let h0 = split(&v.serialize()).header;
    v.upgrade_format(&pw(FPW), 9_000).expect("no-op is Ok");
    let b = v.serialize();
    assert_eq!(split(&b).header, h0, "header unchanged (slots, stamp)");
    LockedVault::parse(&b).unwrap().unlock_with_kek(sid, &kek).expect("enclave slot kept");
    // even with a wrong password, a no-op should not destroy anything
    let r = v.upgrade_format(&pw("wrong"), 9_500);
    assert_eq!(split(&v.serialize()).header, h0, "header unchanged after no-op with wrong password ({r:?})");
}

/// 02 upgrade_format(password, ..) with a wrong password: refused, nothing changed.
#[test]
fn u03_upgrade_wrong_password() {
    let (mut v, sid, kek) = v1_with_extra_slots();
    let h0 = split(&v.serialize()).header;
    let r = v.upgrade_format(&pw("not the password"), 5_000);
    assert!(matches!(r, Err(VaultError::WrongPassword)), "{r:?}");
    let b = v.serialize();
    assert_eq!(version_of(&b), 1, "still version 1");
    assert_eq!(split(&b).header, h0, "header untouched");
    LockedVault::parse(&b).unwrap().unlock_with_kek(sid, &kek).expect("enclave slot still there");
}

/// 01 §9 on a committed v1 fixture: v1-basic upgrades, opens, contents and derived ids unchanged.
#[test]
fn u04_upgrade_fixture() {
    for name in ["v1-basic.vault", "v1-stamped.vault", "v1-forward.vault", "v1-meta.vault", "v1-icon.vault"] {
        let b = fixture(name);
        let mut v = LockedVault::parse(&b).unwrap().unlock(&pw(FPW)).unwrap();
        let ids = field_ids(&v);
        let s0 = snap_vault(&v);
        v.upgrade_format(&pw(FPW), 1_900_000_000_000).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let out = v.serialize();
        assert_eq!(version_of(&out), 2, "{name}");
        let u = LockedVault::parse(&out).unwrap().unlock(&pw(FPW)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(field_ids(&u), ids, "{name}: ids");
        assert_eq!(snap_vault(&u), s0, "{name}: contents");
        indep::open_file(&out, FPW);
    }
}

/// 03 §5 header merge + 01 §9: one device upgrades (v2), the other still holds the v1 file in
/// memory. Whatever the merge direction, the merged vault must serialize to a file that opens
/// with the password (the version and the slot AADs must agree).
#[test]
fn u05_merge_across_versions_stays_openable() {
    let b = fixture("v1-stamped.vault");
    let l = LockedVault::parse(&b).unwrap();
    let mut a = l.unlock(&pw(FPW)).unwrap(); // stays v1
    let mut up = l.unlock(&pw(FPW)).unwrap();
    up.upgrade_format(&pw(FPW), 1_900_000_000_000).unwrap();
    let id = a.items().next().unwrap().id;
    let fid = a.get(id).unwrap().fields[0].id;
    a.set_field(id, fid, pw("edit-on-v1"), 1_900_000_000_100).unwrap();
    // v1 device pulls the upgraded file
    let disk_up = LockedVault::parse(&up.serialize()).unwrap().unlock_with_key(&a.export_vault_key(), a.device_id()).unwrap();
    let mut a2 = LockedVault::parse(&a.serialize()).unwrap().unlock(&pw(FPW)).unwrap();
    a2.merge_from(&disk_up).unwrap();
    let out = a2.serialize();
    let mut bad = vec![];
    let r = LockedVault::parse(&out).and_then(|l| l.unlock(&pw(FPW)));
    if r.is_err() {
        bad.push(format!("v1 <- v2: writes version {} that does not open: {:?}", version_of(&out), r.err()));
    }
    eprintln!("INFO v1 <- v2 merge writes version {}", version_of(&out));
    // upgraded device pulls the v1 device's file (which has a later field edit)
    let disk_a = LockedVault::parse(&a.serialize()).unwrap().unlock_with_key(&up.export_vault_key(), up.device_id()).unwrap();
    up.merge_from(&disk_a).unwrap();
    let out = up.serialize();
    match LockedVault::parse(&out).and_then(|l| l.unlock(&pw(FPW))) {
        Ok(u) => {
            if version_of(&out) != 2 {
                bad.push(format!("v2 <- v1: went back to version {}", version_of(&out)));
            }
            if u.get(id).unwrap().field_by_id(fid).unwrap().value.expose_secret() != "edit-on-v1" {
                bad.push("v2 <- v1: lost the v1 edit".into());
            }
        }
        Err(e) => bad.push(format!("v2 <- v1: writes version {} that does not open: {e:?}", version_of(&out))),
    }
    // Ported 2026-10-31 to the amended 01 §9: "A merge never lowers a file's version: the header
    // with the greater format_version wins regardless of slots_modified_at ... a slot change made
    // on the older version after another device's upgrade (a password change ...) is dropped by
    // the merge and must be redone on the upgraded vault." Both directions: the merged file is
    // version 2, opens with the OLD password and refuses the new one.
    let mut c = l.unlock(&pw(FPW)).unwrap();
    c.change_password(&pw(FPW), &pw("new pass phrase"), KdfParams::for_tests(), 1_950_000_000_000).unwrap();
    let mut up2 = l.unlock(&pw(FPW)).unwrap();
    up2.upgrade_format(&pw(FPW), 1_900_000_000_000).unwrap();
    let disk_c = LockedVault::parse(&c.serialize()).unwrap().unlock_with_key(&up2.export_vault_key(), up2.device_id()).unwrap();
    let disk_up2 = LockedVault::parse(&up2.serialize()).unwrap().unlock_with_key(&c.export_vault_key(), c.device_id()).unwrap();
    up2.merge_from(&disk_c).unwrap();
    c.merge_from(&disk_up2).unwrap();
    for (label, out) in [("v2 <- newer v1 header", up2.serialize()), ("v1 (newer header) <- v2", c.serialize())] {
        if version_of(&out) != 2 {
            bad.push(format!("{label}: merged file is version {}, want 2", version_of(&out)));
        }
        let l = LockedVault::parse(&out).unwrap();
        if let Err(e) = l.unlock(&pw(FPW)) {
            bad.push(format!("{label}: does not open with the OLD password: {e:?}"));
        }
        if l.unlock(&pw("new pass phrase")).is_ok() {
            bad.push(format!("{label}: still opens with the new password made on the v1 side"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn put_fixture_package(dir: &std::path::Path, name: &str, fixture_name: &str) -> std::path::PathBuf {
    let pkg = dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("vault.bin"), fixture(fixture_name)).unwrap();
    pkg
}
fn open_dev(pkg: &std::path::Path, password: &str) -> Dev {
    let dev = Uuid::new_v4();
    let mut s = SyncedVault::open(pkg, dev, hooks()).unwrap();
    let rx = s.subscribe();
    s.unlock(&pw(password)).unwrap();
    Dev { s, rx, seen: vec![], dev }
}

/// 03 §3 pre-write merge + 01 §9 through vault-sync: two handles on one package; A optionally
/// upgrades and saves; B (same build, holding the old state) edits the title and saves. The
/// upgrade must survive, B's edit must land, and the file must open with the password. Then A
/// edits `favorite` on its stale copy (title still the original) and saves.
/// Ported 2026-10-31 to 03 §5 "metadata (title, kind, favorite, tags) taken from whichever item
/// has the greater modified_at": item metadata merges as one block, so A's later favorite edit
/// wins whole and B's title edit is replaced by A's stale title. The `upgraded = false` variant
/// shows the same outcome without any upgrade, so the loss is the metadata rule, not the upgrade.
fn metadata_block_case(upgraded: bool) {
    let d = tempdir();
    let fx = if upgraded { "v1-basic.vault" } else { "v2-basic.vault" };
    let pkg = put_fixture_package(d.path(), "up.vault", fx);
    let mut a = open_dev(&pkg, FPW);
    let mut b = open_dev(&pkg, FPW);
    let id = b.v().items().next().unwrap().id;
    let original = b.v().get(id).unwrap().title.clone();
    if upgraded {
        a.s.edit(|v| v.upgrade_format(&pw(FPW), now_ms())).unwrap().unwrap();
        a.s.save().unwrap();
    }
    assert_eq!(version_of(&std::fs::read(primary(&pkg)).unwrap()), 2);
    b.s.edit(|v| v.update(id, now_ms(), |it| it.title = "edited on B".into())).unwrap().unwrap();
    let r = b.s.save();
    b.drain();
    assert!(r.is_ok(), "B's save (upgraded={upgraded}): {r:?}; events {:?}", b.seen);
    let disk = std::fs::read(primary(&pkg)).unwrap();
    assert_eq!(version_of(&disk), 2, "version 2 survives B's save");
    let u = LockedVault::parse(&disk).unwrap().unlock(&pw(FPW)).expect("file opens after both saves");
    assert_eq!(u.get(id).unwrap().title, "edited on B");
    std::thread::sleep(std::time::Duration::from_millis(5));
    a.s.edit(|v| v.update(id, now_ms(), |it| it.favorite = true)).unwrap().unwrap();
    a.s.save().unwrap();
    let u = LockedVault::parse(&std::fs::read(primary(&pkg)).unwrap()).unwrap().unlock(&pw(FPW)).unwrap();
    let it = u.get(id).unwrap();
    assert!(it.favorite, "later metadata edit (favorite) wins (upgraded={upgraded})");
    assert_eq!(it.title, original, "metadata wins as one block: A's stale title replaces B's earlier edit (upgraded={upgraded})");
}

#[test]
fn u06_sync_upgrade_on_one_handle_survives_other_save() {
    metadata_block_case(true);
}

#[test]
fn u06b_same_metadata_outcome_without_upgrade() {
    metadata_block_case(false);
}

/// Same as u06 but B learns about the upgrade through the watcher (03 §3 step 6) before saving.
#[test]
fn u07_sync_upgrade_seen_by_watcher() {
    let d = tempdir();
    let pkg = put_fixture_package(d.path(), "upw.vault", "v1-basic.vault");
    let mut a = open_dev(&pkg, FPW);
    let mut b = open_dev(&pkg, FPW);
    b.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.s.edit(|v| v.upgrade_format(&pw(FPW), now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    b.wait_for(5, |e| e.iter().any(|x| x.starts_with("Merged") || x.starts_with("SaveBlocked") || x.starts_with("Error") || x.starts_with("KeyMismatch")));
    let id = b.v().items().next().unwrap().id;
    b.s.edit(|v| v.update(id, now_ms(), |it| it.title = "B after watch".into())).unwrap().unwrap();
    let r = b.s.save();
    b.drain();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let u = LockedVault::parse(&disk).and_then(|l| l.unlock(&pw(FPW)));
    assert!(r.is_ok() && u.is_ok() && version_of(&disk) == 2, "save {r:?}; version {}; opens {:?}; events {:?}", version_of(&disk), u.as_ref().err(), b.seen);
    assert_eq!(u.unwrap().get(id).unwrap().title, "B after watch");
}

/// Diagnostic for u06: what the broken file is. Slots wrapped for version 2 inside a version 1
/// file (01 §2 slot AAD = magic || format_version || ...), so no password opens it; the cached
/// key path still does, which hides the damage until the next password unlock.
#[test]
fn u08_diagnose_version_slot_mismatch() {
    let d = tempdir();
    let pkg = put_fixture_package(d.path(), "diag.vault", "v1-basic.vault");
    let mut a = open_dev(&pkg, FPW);
    let mut b = open_dev(&pkg, FPW);
    let id = b.v().items().next().unwrap().id;
    a.s.edit(|v| v.upgrade_format(&pw(FPW), now_ms())).unwrap().unwrap();
    a.s.save().unwrap();
    b.s.edit(|v| v.update(id, now_ms(), |it| it.title = "x".into())).unwrap().unwrap();
    b.s.save().unwrap();
    let disk = std::fs::read(primary(&pkg)).unwrap();
    let raw = split(&disk);
    let h = &raw.header;
    let kdf = get(h, "kdf").unwrap();
    let kek = indep::kek_password(FPW, &bytes_of(get(kdf, "salt").unwrap()), u64_of(get(kdf, "m_cost").unwrap()) as u32, u64_of(get(kdf, "t_cost").unwrap()) as u32, u64_of(get(kdf, "p_cost").unwrap()) as u32);
    let vid = bytes_of(get(h, "vault_id").unwrap());
    let s = &get(h, "slots").unwrap().as_array().unwrap()[0];
    let try_v = |ver: u16| indep::open(&kek, &bytes_of(get(s, "nonce").unwrap()), &bytes_of(get(s, "wrapped_key").unwrap()), &indep::slot_aad(ver, &vid, &bytes_of(get(s, "id").unwrap()), "password")).is_some();
    let l = LockedVault::parse(&disk).unwrap();
    let pw_ok = l.unlock(&pw(FPW)).is_ok();
    let key_ok = l.unlock_with_key(&b.v().export_vault_key(), Uuid::new_v4()).is_ok();
    let backups = ls(&pkg.join("backups"));
    eprintln!("INFO file version {}; slot opens with v1 AAD: {}; with v2 AAD: {}; password unlock ok: {pw_ok}; cached-key unlock ok: {key_ok}; backups {backups:?}", raw.version, try_v(1), try_v(2));
    assert!(pw_ok, "vault no longer opens with its password after a v1 handle saved over an upgrade");
}

/// 03 §6 conflict copies of BOTH shapes across versions: the primary is v1 and held by A; another
/// device upgraded and its write landed as a conflict copy. Absorbing it must leave a primary that
/// opens with the password (and the copy is moved to backups, never deleted).
#[test]
fn u09_conflict_copy_from_upgraded_device() {
    let mut bad = vec![];
    for shape in ["in-package", "sibling"] {
        let d = tempdir();
        let pkg = put_fixture_package(d.path(), "cc.vault", "v1-basic.vault");
        let mut a = open_dev(&pkg, FPW);
        a.s.start_watching().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(700));
        let mut other = LockedVault::parse(&fixture("v1-basic.vault")).unwrap().unlock(&pw(FPW)).unwrap();
        other.upgrade_format(&pw(FPW), now_ms()).unwrap();
        let dev = other.device_id();
        let new_id = other.insert(Item::new("from upgraded device", dev, now_ms()), now_ms());
        let bytes = other.serialize();
        if shape == "in-package" {
            std::fs::write(pkg.join("vault 2.bin"), &bytes).unwrap();
        } else {
            let sib = d.path().join("cc 2.vault");
            std::fs::create_dir_all(&sib).unwrap();
            std::fs::write(sib.join("vault.bin"), &bytes).unwrap();
        }
        a.wait_for(6, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
        let disk = std::fs::read(primary(&pkg)).unwrap();
        match LockedVault::parse(&disk).and_then(|l| l.unlock(&pw(FPW))) {
            Ok(u) => {
                if u.get(new_id).is_none() {
                    bad.push(format!("{shape}: absorbed item missing; events {:?}", a.seen));
                }
            }
            Err(e) => bad.push(format!("{shape}: primary version {} no longer opens with the password: {e:?}; events {:?}", version_of(&disk), a.seen)),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
