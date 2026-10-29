//! Guarantees 1-3, canonical CBOR, unknown-key preservation.

mod common;

use ciborium::Value;
use common::*;
use vault_core::format::{self, FORMAT_VERSION, PREFIX_LEN, VaultFile};
use vault_core::{ExposeSecret, LockedVault, VaultError};

#[test]
fn guarantee_1_roundtrip_100_items() {
    let mut v = new_vault();
    populate(&mut v, 100);
    assert_eq!(v.items().count(), 100);
    let bytes = v.serialize();

    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(locked.vault_id(), v.vault_id());
    assert_eq!(locked.item_summaries().count(), 100);
    let mut summaries: Vec<_> = locked.item_summaries().collect();
    let mut expected: Vec<_> = v.items().map(|i| (i.id, i.modified_at)).collect();
    summaries.sort();
    expected.sort();
    assert_eq!(summaries, expected, "plaintext summaries match");

    let u = locked.unlock(&pw()).unwrap();
    assert_vaults_eq(&v, &u);

    // Spot-check that secrets really went through encryption and back.
    let any = u.items().next().unwrap();
    let totp = any.field("totp").unwrap();
    assert!(totp.value.expose_secret().starts_with("otpauth://totp/"));
    assert!(any.field("password").is_some());
    assert_eq!(any.device_id, device(), "insert stamps device_id");
}

#[test]
fn insert_stamps_modified_at_and_device_id() {
    let mut v = new_vault();
    let mut item = sample_item(1, 500);
    item.modified_at = 500;
    let id = v.insert(item.clone(), 1000);
    assert_eq!(v.get(id).unwrap().modified_at, 1000);
    assert_eq!(v.get(id).unwrap().device_id, device());

    item.modified_at = 2000;
    v.insert(item, 1000);
    assert_eq!(
        v.get(id).unwrap().modified_at,
        2000,
        "keeps newer modified_at"
    );
    assert_eq!(v.items_including_deleted().count(), 1, "same id replaces");
}

#[test]
fn items_excludes_tombstones() {
    let mut v = new_vault();
    let mut dead = sample_item(1, 10);
    dead.deleted_at = Some(20);
    dead.fields.clear();
    let dead_id = v.insert(dead, 20);
    let live_id = v.insert(sample_item(2, 10), 10);
    assert_eq!(v.items().map(|i| i.id).collect::<Vec<_>>(), vec![live_id]);
    assert_eq!(v.items_including_deleted().count(), 2);
    assert!(v.get(dead_id).unwrap().is_deleted());

    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    assert_eq!(u.items().count(), 1);
}

#[test]
fn guarantee_2_serialize_twice_differs_but_unlocks_equal() {
    let mut v = new_vault();
    populate(&mut v, 5);
    let a = v.serialize();
    let b = v.serialize();
    assert_ne!(a, b, "fresh nonces every call");
    assert_eq!(a.len(), b.len());
    let ua = unlock(&a).unwrap();
    let ub = unlock(&b).unwrap();
    assert_vaults_eq(&ua, &ub);
    assert_vaults_eq(&v, &ua);

    // Nonces differ per record.
    let fa = VaultFile::parse(&a).unwrap();
    let fb = VaultFile::parse(&b).unwrap();
    for (x, y) in fa.items.iter().zip(&fb.items) {
        assert_eq!(x.id, y.id);
        assert_ne!(x.nonce, y.nonce);
        assert_ne!(x.ct, y.ct);
    }
    assert_ne!(fa.manifest.nonce, fb.manifest.nonce);
}

#[test]
fn guarantee_3_wrong_password() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let bytes = v.serialize();
    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(
        locked
            .unlock(&secret("correct horse battery stapl"))
            .unwrap_err(),
        VaultError::WrongPassword
    );
    assert_eq!(
        locked.unlock(&secret("")).unwrap_err(),
        VaultError::WrongPassword
    );
    // Empty vault too.
    let empty = new_vault().serialize();
    assert_eq!(
        LockedVault::parse(&empty)
            .unwrap()
            .unlock(&secret("nope"))
            .unwrap_err(),
        VaultError::WrongPassword
    );
    assert!(LockedVault::parse(&empty).unwrap().unlock(&pw()).is_ok());
}

#[test]
fn password_nfc_normalised_at_unlock() {
    let v = UnlockedVault_with_password("caf\u{e9}");
    let bytes = v.serialize();
    let locked = LockedVault::parse(&bytes).unwrap();
    assert!(locked.unlock(&secret("cafe\u{301}")).is_ok());
    assert_eq!(
        locked.unlock(&secret("cafe")).unwrap_err(),
        VaultError::WrongPassword
    );
}

#[allow(non_snake_case)]
fn UnlockedVault_with_password(p: &str) -> vault_core::UnlockedVault {
    vault_core::UnlockedVault::create(&secret(p), vault_core::KdfParams::for_tests(), device())
}

fn header_slice(bytes: &[u8]) -> &[u8] {
    let len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    &bytes[PREFIX_LEN..PREFIX_LEN + len]
}

#[test]
fn canonical_cbor_header_is_stable_and_sorted() {
    let mut v = new_vault();
    populate(&mut v, 3);
    let a = v.serialize();
    let b = v.serialize();
    assert_eq!(&a[..PREFIX_LEN], &b[..PREFIX_LEN]);
    assert_eq!(&a[..4], b"RVLT");
    assert_eq!(u16::from_be_bytes([a[4], a[5]]), FORMAT_VERSION);
    assert_eq!(
        header_slice(&a),
        header_slice(&b),
        "header bytes identical across serializes"
    );
    assert_ne!(
        &a[PREFIX_LEN + header_slice(&a).len()..],
        &b[PREFIX_LEN + header_slice(&b).len()..]
    );

    // Decode header -> Value -> re-encode yields identical bytes, and the tree is canonical.
    let hb = header_slice(&a);
    let value: Value = ciborium::from_reader(hb).unwrap();
    assert!(
        format::is_canonical(&value),
        "header map keys in canonical order"
    );
    let mut re = Vec::new();
    ciborium::into_writer(&value, &mut re).unwrap();
    assert_eq!(re, hb);

    // Same through the typed path.
    let header = vault_core::Header::from_bytes(hb, FORMAT_VERSION).unwrap();
    assert_eq!(header.format_version, FORMAT_VERSION);
    assert_eq!(header.to_bytes(), hb);

    // Body is canonical too.
    let body: Value = ciborium::from_reader(&a[PREFIX_LEN + hb.len()..]).unwrap();
    assert!(format::is_canonical(&body));
}

#[test]
fn canonical_cbor_item_plain() {
    let item = sample_item(3, 42);
    let plain = format::encode_item_plain(&item);
    let value: Value = ciborium::from_reader(plain.as_slice()).unwrap();
    assert!(format::is_canonical(&value));
    let Value::Map(entries) = &value else {
        panic!("ItemPlain is a map")
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.as_str(),
            _ => panic!("text keys"),
        })
        .collect();
    assert_eq!(
        keys,
        [
            "kind",
            "tags",
            "title",
            "fields",
            "history",
            "favorite",
            "device_id",
            "deleted_at",
            "attachments"
        ]
    );
    let back = format::decode_item_plain(&plain, item.id, item.modified_at).unwrap();
    assert_item_eq(&item, &back);
}

#[test]
fn unknown_keys_survive_roundtrip() {
    let mut v = new_vault();
    let mut item = sample_item(1, 10);
    item.extras
        .push((Value::Text("x_future".into()), Value::Integer(7.into())));
    // A known key in extras collides with the real field and is dropped, never duplicated.
    item.extras.push((
        Value::Text("attachments".into()),
        Value::Array(vec![Value::Map(vec![(
            Value::Text("id".into()),
            Value::Bytes(vec![1; 16]),
        )])]),
    ));
    let mut att = vault_core::attachment::new_ref("note.txt", 5, 10).unwrap();
    att.extras
        .push((Value::Text("x_att_future".into()), Value::Integer(9.into())));
    let att_id = att.id;
    item.attachments.push(att);
    item.fields[0]
        .extras
        .push((Value::Text("x_field_future".into()), Value::Bool(true)));
    let id = v.insert(item, 10);
    v.header_extras_mut().push((
        Value::Text("x_header_future".into()),
        Value::Text("hi".into()),
    ));
    let bytes = v.serialize();

    // Add unknown keys at the file layer too: kdf map, slot, item record, manifest record.
    let bytes = rewrite(&bytes, |f| {
        f.header
            .kdf_extras
            .push((Value::Text("x_kdf".into()), Value::Integer(1.into())));
        f.header.slots[0]
            .as_key_mut()
            .unwrap()
            .extras
            .push((Value::Text("x_slot".into()), Value::Integer(2.into())));
        f.items[0]
            .extras
            .push((Value::Text("x_rec".into()), Value::Integer(3.into())));
        f.manifest
            .extras
            .push((Value::Text("x_man".into()), Value::Integer(4.into())));
    });

    let u = unlock(&bytes).unwrap();
    let got = u.get(id).unwrap();
    assert!(
        got.extras
            .iter()
            .any(|(k, _)| k == &Value::Text("x_future".into()))
    );
    assert!(
        !got.extras
            .iter()
            .any(|(k, _)| k == &Value::Text("attachments".into())),
        "a colliding extra never shadows the parsed attachments"
    );
    let att = got.attachment(att_id).unwrap();
    assert_eq!(att.name, "note.txt");
    assert!(
        att.extras
            .iter()
            .any(|(k, _)| k == &Value::Text("x_att_future".into()))
    );
    assert!(
        got.fields[0]
            .extras
            .iter()
            .any(|(k, _)| k == &Value::Text("x_field_future".into()))
    );

    let out = u.serialize();
    let f = VaultFile::parse(&out).unwrap();
    let has = |extras: &Vec<(Value, Value)>, k: &str| {
        extras.iter().any(|(kk, _)| kk == &Value::Text(k.into()))
    };
    assert!(has(&f.header.extras, "x_header_future"));
    assert!(has(&f.header.kdf_extras, "x_kdf"));
    assert!(has(&f.header.slots[0].as_key().unwrap().extras, "x_slot"));
    assert!(has(&f.items[0].extras, "x_rec"));
    assert!(has(&f.manifest.extras, "x_man"));
    let hv: Value = ciborium::from_reader(header_slice(&out)).unwrap();
    assert!(
        format::is_canonical(&hv),
        "extras sorted into canonical position"
    );

    let u2 = unlock(&out).unwrap();
    assert_vaults_eq(&u, &u2);
    // Exactly one attachments array, holding the real reference (with its extra), not the
    // colliding junk.
    let plain = format::encode_item_plain(u2.get(id).unwrap());
    let pv: Value = ciborium::from_reader(plain.as_slice()).unwrap();
    let Value::Map(entries) = pv else { panic!() };
    let att: Vec<_> = entries
        .iter()
        .filter(|(k, _)| k == &Value::Text("attachments".into()))
        .collect();
    assert_eq!(att.len(), 1);
    let Value::Array(refs) = &att[0].1 else {
        panic!()
    };
    assert_eq!(refs.len(), 1);
    let Value::Map(m) = &refs[0] else { panic!() };
    assert!(
        m.iter()
            .any(|(k, _)| k == &Value::Text("x_att_future".into()))
    );
    assert!(m.iter().any(|(k, _)| k == &Value::Text("key".into())));
}
