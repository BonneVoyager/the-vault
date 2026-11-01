//! Cross-device edge cases for vault-sync (03 §3, §5, §6, §8).
use secrecy::ExposeSecret;
use spec_checks::dev::*;
use spec_checks::*;
use vault_core::*;

fn val(v: &UnlockedVault, id: uuid::Uuid, name: &str) -> Option<String> {
    v.get(id)?
        .fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.expose_secret().clone())
}
fn hex(id: uuid::Uuid) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// 03 §3 "While the app holds unsaved edits ... step 6 still runs ... the next save writes both."
#[test]
fn e01_dirty_merge_keeps_both() {
    let d = tempdir();
    let pkg = d.path().join("dm.vault");
    let mut a = Dev::create(&pkg);
    let id = a.add_login("x", now_ms());
    a.s.save().unwrap();
    let mut b = Dev::open(&pkg);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    a.s.edit(|v| v.set_field_named(id, "username", pw("a-dirty"), now_ms()))
        .unwrap()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    b.s.edit(|v| v.set_field_named(id, "password", pw("b-saved"), now_ms()))
        .unwrap()
        .unwrap();
    let bid = b.add_login("b-new", now_ms());
    b.s.save().unwrap();
    a.wait_for(8, |e| e.iter().any(|x| x.starts_with("Merged")));
    assert_eq!(
        val(a.v(), id, "password").as_deref(),
        Some("b-saved"),
        "events {:?}",
        a.seen
    );
    assert_eq!(
        val(a.v(), id, "username").as_deref(),
        Some("a-dirty"),
        "unsaved edit kept"
    );
    a.s.save().unwrap();
    let disk = read_vault(&pkg);
    assert_eq!(val(&disk, id, "username").as_deref(), Some("a-dirty"));
    assert_eq!(val(&disk, id, "password").as_deref(), Some("b-saved"));
    assert!(disk.get(bid).is_some());
}

/// 03 §6 step 4: whole-package move deferred while blobs referenced by merged items are missing
/// from both sides; a late blob re-triggers it.
#[test]
fn e02_whole_package_deferred_until_blob() {
    let d = tempdir();
    let pkg = d.path().join("df.vault");
    let mut a = Dev::create(&pkg);
    let item = a.add_login("host", now_ms());
    a.s.save().unwrap();
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    let aid =
        c.s.add_attachment(item, "late.txt", &b"late blob"[..], 9, now_ms())
            .unwrap();
    c.s.save().unwrap();
    drop(c);
    let blob_name = format!("{}.bin", hex(aid));
    let held = std::fs::read(staging.join("attachments").join(&blob_name)).unwrap();
    std::fs::remove_file(staging.join("attachments").join(&blob_name)).unwrap();
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let target = d.path().join("df 2.vault");
    std::fs::rename(&staging, &target).unwrap();
    a.wait_for(4, |_| false);
    assert!(
        target.exists(),
        "moved although its blob is missing on both sides; events {:?}",
        a.seen
    );
    std::fs::write(target.join("attachments").join(&blob_name), &held).unwrap();
    let got = a.wait_for(8, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
    assert!(got, "late blob re-triggers the move; events {:?}", a.seen);
    assert!(!target.exists());
    assert!(
        pkg.join("attachments").join(&blob_name).exists(),
        "blob copied before the move"
    );
}

/// 03 §5 + §6: a conflict copy carrying a newer password change is absorbed and the header adopted.
#[test]
fn e03_conflict_copy_with_password_change() {
    let d = tempdir();
    let pkg = d.path().join("hp.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let st = tempdir();
    let staging = st.path().join("staging.vault");
    copy_dir(&pkg, &staging);
    let mut c = Dev::open(&staging);
    c.s.edit(|v| {
        v.change_password(
            &pw(PW),
            &pw("conflict new pass"),
            KdfParams::for_tests(),
            now_ms(),
        )
    })
    .unwrap()
    .unwrap();
    c.s.save().unwrap();
    drop(c);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    std::fs::copy(staging.join("vault.bin"), pkg.join("vault 2.bin")).unwrap();
    let got = a.wait_for(8, |e| e.iter().any(|x| x.starts_with("ConflictAbsorbed")));
    assert!(got, "{:?}", a.seen);
    let l = LockedVault::parse(&std::fs::read(primary(&pkg)).unwrap()).unwrap();
    assert!(
        l.unlock(&pw("conflict new pass")).is_ok(),
        "password change from conflict copy adopted"
    );
    assert!(l.unlock(&pw(PW)).is_err());
}

/// 01 §4 header_digest + 03 §6: a forged header stamp in a conflict copy (file-writing attacker)
/// does not verify; the copy is not absorbed into the header and is never deleted.
#[test]
fn e04_forged_conflict_header_rejected() {
    let d = tempdir();
    let pkg = d.path().join("fh.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.edit(|v| v.change_password(&pw(PW), &pw("pw two two"), KdfParams::for_tests(), now_ms()))
        .unwrap()
        .unwrap();
    a.s.save().unwrap();
    let good = std::fs::read(primary(&pkg)).unwrap();
    let raw = split(&good);
    let mut h = raw.header.clone();
    set(
        &mut h,
        "slots_modified_at",
        Value::Integer((now_ms() + 10_000_000).into()),
    );
    // attacker drops the slot list to only an opaque slot to lock the user out
    set(
        &mut h,
        "slots",
        Value::Array(vec![Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(vec![1; 16])),
            (Value::Text("kind".into()), Value::Text("evil".into())),
        ])]),
    );
    let forged = join(raw.version, &h, &raw.body);
    a.s.start_watching().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    std::fs::write(pkg.join("vault 2.bin"), &forged).unwrap();
    a.wait_for(4, |_| false);
    let l = LockedVault::parse(&std::fs::read(primary(&pkg)).unwrap()).unwrap();
    assert!(
        l.unlock(&pw("pw two two")).is_ok(),
        "primary still opens with the real password; events {:?}",
        a.seen
    );
    let kept = pkg.join("vault 2.bin").exists()
        || ls(&pkg.join("backups"))
            .iter()
            .any(|n| n.contains("vault 2"));
    assert!(kept, "never delete a conflict copy");
}

/// Restoring a backup of a *different* vault would silently swap vault_id under the handle.
#[test]
fn e05_restore_foreign_backup_refused() {
    let d = tempdir();
    let pkg = d.path().join("rf.vault");
    let mut a = Dev::create(&pkg);
    a.add_login("x", now_ms());
    a.s.save().unwrap();
    let o = tempdir();
    let opkg = o.path().join("other.vault");
    let mut b = Dev::create(&opkg);
    b.s.save().unwrap();
    let foreign = b.s.backup_now().unwrap();
    let before = a.v().vault_id();
    let r = a.s.restore_from(&foreign, &pw(PW));
    let disk = read_vault(&pkg);
    assert!(
        r.is_err() || disk.vault_id() == before,
        "restore_from replaced the vault with a foreign vault_id"
    );
}

/// 03 §5 header LWW under clock skew: a device whose clock ran ahead changed the password; a
/// later change on a correct-clock device must still win ("every write stamps max(now, prev+1)"
/// is stated for items; header changes are the same LWW mechanism).
#[test]
fn e06_header_stamp_monotone_under_skew() {
    let base = UnlockedVault::create(&pw("p0"), KdfParams::for_tests(), uuid::Uuid::new_v4());
    let bytes = base.serialize();
    let k = base.export_vault_key();
    let mut ahead = LockedVault::parse(&bytes)
        .unwrap()
        .unlock_with_key(&k, uuid::Uuid::new_v4())
        .unwrap();
    let mut normal = LockedVault::parse(&bytes)
        .unwrap()
        .unlock_with_key(&k, uuid::Uuid::new_v4())
        .unwrap();
    ahead
        .change_password(&pw("p0"), &pw("p-ahead"), KdfParams::for_tests(), 2_000_000)
        .unwrap();
    let theirs = LockedVault::parse(&ahead.serialize())
        .unwrap()
        .unlock_with_key(&k, normal.device_id())
        .unwrap();
    normal.merge_from(&theirs).unwrap();
    // the user, on the normal device, changes the password again later in real time (clock = 1_000_000)
    normal
        .change_password(
            &pw("p-ahead"),
            &pw("p-final"),
            KdfParams::for_tests(),
            1_000_000,
        )
        .unwrap();
    let hdr = split(&normal.serialize()).header;
    let stamp = u64_of(get(&hdr, "slots_modified_at").unwrap());
    assert!(
        stamp > 2_000_000,
        "slots_modified_at went backwards: {stamp}"
    );
    let back = LockedVault::parse(&normal.serialize())
        .unwrap()
        .unlock_with_key(&k, ahead.device_id())
        .unwrap();
    ahead.merge_from(&back).unwrap();
    assert!(
        LockedVault::parse(&ahead.serialize())
            .unwrap()
            .unlock(&pw("p-final"))
            .is_ok(),
        "latest password change lost to a skewed clock"
    );
}

/// 03 §3 "Merge is idempotent and commutative, so a ping-pong between two devices converges in
/// one round trip each", through vault-sync with two handles on one package. Same-millisecond
/// edits of one field on both handles plus a later title edit on B (see merge_ids mi10): after
/// several save/merge rounds both handles and the file should agree on the field value.
#[test]
fn e10_same_stamp_field_edit_converges_through_sync() {
    use vault_core::*;
    let d = tempdir();
    let pkg = d.path().join("tie.vault");
    let dev_a = uuid::Uuid::from_bytes([0xF0; 16]);
    let dev_b = uuid::Uuid::from_bytes([0x10; 16]);
    let mut a = SyncedVault::create(&pkg, &pw(PW), KdfParams::for_tests(), dev_a, hooks()).unwrap();
    let t0 = now_ms();
    let (id, fid) = a
        .edit(|v| {
            let mut it = Item::new("Tie", dev_a, t0);
            it.fields
                .push(Field::new("username", FieldKind::Text, pw("u0"), t0));
            let f = it.fields[0].id;
            (v.insert(it, t0), f)
        })
        .unwrap();
    a.save().unwrap();
    let mut b = SyncedVault::open(&pkg, dev_b, hooks()).unwrap();
    b.unlock(&pw(PW)).unwrap();
    let t = t0 + 10_000;
    a.edit(|v| v.set_field(id, fid, pw("from-A"), t))
        .unwrap()
        .unwrap();
    b.edit(|v| v.set_field(id, fid, pw("from-B"), t))
        .unwrap()
        .unwrap();
    b.edit(|v| v.update(id, t + 100, |it| it.title = "B title".into()))
        .unwrap()
        .unwrap();
    b.save().unwrap();
    for _ in 0..3 {
        a.edit(|_| ()).unwrap();
        a.save().unwrap();
        b.edit(|_| ()).unwrap();
        b.save().unwrap();
    }
    let get_v = |s: &SyncedVault| {
        s.vault()
            .unwrap()
            .get(id)
            .unwrap()
            .field_by_id(fid)
            .unwrap()
            .value
            .expose_secret()
            .clone()
    };
    let disk = read_vault(&pkg);
    let on_disk = disk
        .get(id)
        .unwrap()
        .field_by_id(fid)
        .unwrap()
        .value
        .expose_secret()
        .clone();
    let (va, vb) = (get_v(&a), get_v(&b));
    assert!(
        va == vb && vb == on_disk,
        "A shows {va:?}, B shows {vb:?}, file has {on_disk:?}"
    );
}
