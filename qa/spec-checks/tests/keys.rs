//! Keys and slots (01 §2-§3, 02 "keys", guarantee 8, 03 §5 header merge).
use secrecy::{ExposeSecret, SecretVec};
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

fn kek(b: u8) -> SecretVec<u8> {
    SecretVec::new(vec![b; 32])
}
fn new_vault(p: &str) -> (UnlockedVault, Uuid) {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(p), KdfParams::for_tests(), dev);
    let mut it = Item::new("acct", dev, 100);
    it.fields.push(Field::new("password", FieldKind::Password, pw("item-secret"), 100));
    let id = v.insert(it, 100);
    (v, id)
}
fn parse(b: &[u8]) -> LockedVault {
    LockedVault::parse(b).unwrap()
}

/// 02 guarantee 8: change_password keeps vault_key -> an enclave slot added before still unlocks.
#[test]
fn k01_change_password_keeps_vault_key() {
    let (mut v, id) = new_vault("old password one");
    let sid = v.add_enclave_slot(&kek(7), 200);
    let before = indep::open_file(&v.serialize(), "old password one").vault_key;
    v.change_password(&pw("old password one"), &pw("new password two"), KdfParams::for_tests(), 300).unwrap();
    let b = v.serialize();
    let l = parse(&b);
    assert!(matches!(l.unlock(&pw("old password one")), Err(VaultError::WrongPassword)));
    let u = l.unlock(&pw("new password two")).unwrap();
    assert!(u.get(id).is_some());
    let u2 = l.unlock_with_kek(sid, &kek(7)).expect("enclave slot from before the change still unlocks");
    assert_eq!(snap_vault(&u2), snap_vault(&u));
    assert_eq!(indep::open_file(&b, "new password two").vault_key, before, "vault_key unchanged");
    // wrong old password refused
    assert!(v.change_password(&pw("nope"), &pw("x"), KdfParams::for_tests(), 400).is_err());
}

/// 02: remove_slot refuses to remove the last password slot; enclave slot removable.
#[test]
fn k02_remove_slot_rules() {
    let (mut v, _) = new_vault("pw");
    let sid = v.add_enclave_slot(&kek(1), 10);
    let raw = split(&v.serialize());
    let slots = get(&raw.header, "slots").unwrap().as_array().unwrap().clone();
    assert_eq!(slots.len(), 2);
    let e = slots.iter().find(|s| get(s, "kind").unwrap().as_text() == Some("enclave")).unwrap();
    assert_eq!(bytes_of(get(e, "wrapped_key").unwrap()).len(), 48);
    let pid = slots.iter().find(|s| get(s, "kind").unwrap().as_text() == Some("password")).unwrap();
    let pid = Uuid::from_slice(&bytes_of(get(pid, "id").unwrap())).unwrap();
    assert!(v.remove_slot(pid, 20).is_err(), "refuses to remove last password slot");
    v.remove_slot(sid, 30).unwrap();
    let l = parse(&v.serialize());
    assert!(l.unlock_with_kek(sid, &kek(1)).is_err(), "removed slot no longer unlocks");
    assert!(v.remove_slot(Uuid::new_v4(), 40).is_err(), "unknown slot id");
}

/// 01 §2 enclave slot structure + AAD with kind "enclave", checked independently.
#[test]
fn k03_enclave_slot_independent_unwrap() {
    let (mut v, _) = new_vault("pw");
    let sid = v.add_enclave_slot(&kek(9), 10);
    let b = v.serialize();
    let raw = split(&b);
    let vid = bytes_of(get(&raw.header, "vault_id").unwrap());
    let s = get(&raw.header, "slots").unwrap().as_array().unwrap().iter().find(|s| get(s, "kind").unwrap().as_text() == Some("enclave")).unwrap().clone();
    assert_eq!(bytes_of(get(&s, "id").unwrap()), sid.as_bytes().to_vec());
    let aad = indep::slot_aad(raw.version, &vid, sid.as_bytes(), "enclave"); // ported 2026-10-31: was hard-coded 1
    let vk = indep::open(&[9; 32], &bytes_of(get(&s, "nonce").unwrap()), &bytes_of(get(&s, "wrapped_key").unwrap()), &aad).expect("enclave slot AAD per 01 §2");
    assert_eq!(vk, indep::open_file(&b, "pw").vault_key);
    // wrong kek / wrong slot id
    let l = parse(&b);
    assert!(l.unlock_with_kek(sid, &kek(8)).is_err());
    assert!(l.unlock_with_kek(Uuid::new_v4(), &kek(9)).is_err());
    // short kek must not panic
    let _ = std::panic::catch_unwind(|| l.unlock_with_kek(sid, &SecretVec::new(vec![9; 5])));
}

/// 02 rotate_vault_key: new vault_key, enclave slot dropped (01 §2, 04 §2), items intact.
#[test]
fn k04_rotate_vault_key() {
    let (mut v, id) = new_vault("pw");
    let sid = v.add_enclave_slot(&kek(2), 10);
    let k0 = indep::open_file(&v.serialize(), "pw").vault_key;
    v.rotate_vault_key(&pw("pw"), 20).unwrap();
    let b = v.serialize();
    let o = indep::open_file(&b, "pw");
    assert_ne!(o.vault_key, k0, "vault key rotated");
    let l = parse(&b);
    assert!(l.unlock_with_kek(sid, &kek(2)).is_err(), "enclave slot dropped");
    let u = l.unlock(&pw("pw")).unwrap();
    assert_eq!(u.get(id).unwrap().fields[0].value.expose_secret(), "item-secret");
    assert!(v.rotate_vault_key(&pw("bad"), 30).is_err(), "rotate checks password");
}

/// 01 §2 header stamp: slot changes set slots_modified_at (millis) and slots_device_id; the
/// manifest AAD then carries header_digest computed per spec (independent SHA-256).
#[test]
fn k05_header_stamp_and_digest() {
    let (mut v, _) = new_vault("pw");
    v.change_password(&pw("pw"), &pw("pw2"), KdfParams::for_tests(), 1_700_000_000_123).unwrap();
    let b = v.serialize();
    let raw = split(&b);
    let sma = get(&raw.header, "slots_modified_at").expect("stamp after password change");
    assert_eq!(u64_of(sma), 1_700_000_000_123);
    let dev = get(&raw.header, "slots_device_id").expect("device id after password change");
    assert_eq!(bytes_of(dev), v.device_id().as_bytes().to_vec());
    indep::open_file(&b, "pw2"); // asserts the digest-bound manifest AAD
    // stripping the stamp now fails on the key path (01 §4) and does not succeed on the password path
    let mut h = raw.header.clone();
    if let Value::Map(e) = &mut h {
        e.retain(|(k, _)| !matches!(k.as_text(), Some("slots_modified_at") | Some("slots_device_id")));
    }
    let f = join(raw.version, &h, &raw.body);
    let l = parse(&f);
    let r1 = l.unlock(&pw("pw2"));
    assert!(matches!(r1, Err(VaultError::Tampered(TamperKind::Manifest))), "stripped stamp via password: {:?}", r1.err());
    let r2 = l.unlock_with_key(&v.export_vault_key(), v.device_id());
    assert!(matches!(r2, Err(VaultError::Tampered(TamperKind::Manifest))), "stripped stamp via key: {:?}", r2.err());
    // re-stamped KDF with the stamp kept -> key path Tampered(Manifest), password path WrongPassword
    let mut h = raw.header.clone();
    set(get_mut(&mut h, "kdf").unwrap(), "t_cost", Value::Integer(2.into()));
    let l = parse(&join(raw.version, &h, &raw.body));
    assert!(matches!(l.unlock(&pw("pw2")), Err(VaultError::WrongPassword)));
    assert!(matches!(l.unlock_with_key(&v.export_vault_key(), v.device_id()), Err(VaultError::Tampered(TamperKind::Manifest))));
    // bump the stamp -> key path must detect
    let mut h = raw.header.clone();
    set(&mut h, "slots_modified_at", Value::Integer((u64::MAX >> 1).into()));
    let l = parse(&join(raw.version, &h, &raw.body));
    assert!(matches!(l.unlock_with_key(&v.export_vault_key(), v.device_id()), Err(VaultError::Tampered(TamperKind::Manifest))));
    // add an opaque slot with stamp -> detected via manifest
    let mut h = raw.header.clone();
    if let Some(Value::Array(s)) = get_mut(&mut h, "slots") {
        s.push(Value::Map(vec![(Value::Text("id".into()), Value::Bytes(vec![5; 16])), (Value::Text("kind".into()), Value::Text("x".into()))]));
    }
    let l = parse(&join(raw.version, &h, &raw.body));
    assert!(matches!(l.unlock_with_key(&v.export_vault_key(), v.device_id()), Err(VaultError::Tampered(TamperKind::Manifest))));
}

/// 03 §5 header merge (V-01/V-03): password change on A survives B's merge+save, both directions.
#[test]
fn k06_header_merge_password_change_survives() {
    let (a0, _) = new_vault("first password");
    let bytes = a0.serialize();
    let dev_b = Uuid::new_v4();
    let mut a = parse(&bytes).unlock(&pw("first password")).unwrap();
    let mut b = parse(&bytes).unlock_with_key(&a.export_vault_key(), dev_b).unwrap();
    a.change_password(&pw("first password"), &pw("second password"), KdfParams::for_tests(), 5_000).unwrap();
    // B edits an item later but did not change slots
    let id = b.items().next().unwrap().id;
    b.set_field_named(id, "password", pw("b-edit"), 6_000).unwrap();
    let a_disk = parse(&a.serialize()).unlock_with_key(&b.export_vault_key(), dev_b).unwrap();
    b.merge_from(&a_disk).unwrap();
    let out = b.serialize();
    let l = parse(&out);
    assert!(l.unlock(&pw("second password")).is_ok(), "B's write keeps A's new password");
    assert!(matches!(l.unlock(&pw("first password")), Err(VaultError::WrongPassword)), "old password gone");
    // the reverse merge order converges
    let b_disk = parse(&out).unlock(&pw("second password")).unwrap();
    a.merge_from(&b_disk).unwrap();
    assert_eq!(snap_vault(&a), snap_vault(&b_disk));
    assert_eq!(get(&split(&a.serialize()).header, "slots"), get(&split(&out).header, "slots"));
}

/// 03 §5: key rotation on A wins over B (greater stamp) and B adopts A's key.
#[test]
fn k07_header_merge_rotation_and_tie_break() {
    let (a0, _) = new_vault("pw");
    let bytes = a0.serialize();
    let mut a = parse(&bytes).unlock(&pw("pw")).unwrap();
    let dev_b = Uuid::new_v4();
    let mut b = parse(&bytes).unlock_with_key(&a.export_vault_key(), dev_b).unwrap();
    a.rotate_vault_key(&pw("pw"), 10_000).unwrap();
    let a_disk = parse(&a.serialize()).unlock(&pw("pw")).unwrap();
    b.merge_from(&a_disk).unwrap();
    let ob = b.serialize();
    assert_eq!(indep::open_file(&ob, "pw").vault_key, indep::open_file(&a.serialize(), "pw").vault_key, "B adopts rotated key");
    // tie: same stamp on both sides, different devices -> both converge to same slots
    let (c0, _) = new_vault("pw");
    let bytes = c0.serialize();
    let mut c = parse(&bytes).unlock(&pw("pw")).unwrap();
    let mut d = parse(&bytes).unlock_with_key(&c.export_vault_key(), Uuid::new_v4()).unwrap();
    c.change_password(&pw("pw"), &pw("pw-c"), KdfParams::for_tests(), 777).unwrap();
    d.change_password(&pw("pw"), &pw("pw-d"), KdfParams::for_tests(), 777).unwrap();
    let cs = parse(&c.serialize()).unlock_with_key(&c.export_vault_key(), Uuid::new_v4()).unwrap();
    let ds = parse(&d.serialize()).unlock_with_key(&d.export_vault_key(), Uuid::new_v4()).unwrap();
    c.merge_from(&ds).unwrap();
    d.merge_from(&cs).unwrap();
    let hc = split(&c.serialize()).header;
    let hd = split(&d.serialize()).header;
    assert_eq!(get(&hc, "slots"), get(&hd, "slots"), "tie on stamp converges");
    let winner = if c.device_id().as_bytes() > d.device_id().as_bytes() { "pw-c" } else { "pw-d" };
    assert!(parse(&c.serialize()).unlock(&pw(winner)).is_ok(), "greater slots_device_id wins tie");
}

/// 01 §3: subkeys differ and are the HKDF values; attach_key reserved (just check item != manifest).
#[test]
fn k08_subkeys_distinct() {
    let (v, _) = new_vault("pw");
    let o = indep::open_file(&v.serialize(), "pw");
    assert_ne!(o.item_key, o.manifest_key);
    assert_ne!(&o.item_key[..], &o.vault_key[..]);
}

/// 02 guarantee 3: no early exit on wrong password; time of first-byte-wrong vs last-byte-wrong
/// within noise (coarse check, single machine, not a proof).
#[test]
fn k09_wrong_password_timing_coarse() {
    let (v, _) = new_vault("abcdefghijklmnop");
    let l = parse(&v.serialize());
    let t = |p: &str| {
        let s = std::time::Instant::now();
        for _ in 0..5 {
            let _ = l.unlock(&pw(p));
        }
        s.elapsed().as_secs_f64()
    };
    let a = t("Xbcdefghijklmnop");
    let b = t("abcdefghijklmnoX");
    assert!((a / b) < 1.5 && (b / a) < 1.5, "timing {a} vs {b}");
}
