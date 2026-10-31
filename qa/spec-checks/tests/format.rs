//! File format and tamper detection (01-vault-format.md, 02 guarantees 1-7).
use secrecy::ExposeSecret;
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

const PW: &str = "correct horse battery staple";

fn sample(n: usize) -> (UnlockedVault, Vec<Uuid>) {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let mut ids = vec![];
    for i in 0..n {
        let mut it = Item::new(format!("item {i}"), dev, 1_000 + i as u64);
        it.fields.push(Field::new("username", FieldKind::Text, pw(&format!("user{i}")), 1_000));
        it.fields.push(Field::new("password", FieldKind::Password, pw(&format!("pw{i}")), 1_000));
        it.tags.push("t".into());
        ids.push(v.insert(it, 1_000 + i as u64));
    }
    (v, ids)
}

fn unlock(b: &[u8]) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(b)?.unlock(&pw(PW))
}

/// 01 §1 layout, §2 header keys, §4 record shapes, "All CBOR is canonical".
#[test]
fn f01_layout_matches_spec() {
    let (v, _) = sample(3);
    let b = v.serialize();
    let raw = split(&b);
    // Rewritten 2026-10-31: 01 §9 "Version 2 (2026-10-31) adds the required field id"; README
    // "Vault format 2 ... is written for new vaults". (01 §1 still says "currently 1"; see report.)
    assert_eq!(raw.version, 2, "01 §9 new vaults are format_version 2");
    let h = &raw.header;
    assert_eq!(bytes_of(get(h, "vault_id").unwrap()).len(), 16);
    let kdf = get(h, "kdf").unwrap();
    assert_eq!(get(kdf, "alg").unwrap().as_text(), Some("argon2id"));
    assert_eq!(bytes_of(get(kdf, "salt").unwrap()).len(), 32);
    let slots = get(h, "slots").unwrap().as_array().unwrap();
    assert!(!slots.is_empty(), "at least one slot");
    for s in slots {
        assert_eq!(bytes_of(get(s, "id").unwrap()).len(), 16);
        assert_eq!(bytes_of(get(s, "nonce").unwrap()).len(), 24);
        assert_eq!(bytes_of(get(s, "wrapped_key").unwrap()).len(), 48);
        assert!(get(s, "created_at").is_some());
    }
    assert!(is_canonical(h), "01: header CBOR canonical");
    assert_eq!(enc(h), raw.header_bytes, "01: header re-encodes byte-identically (canonical, minimal)");
    assert_eq!(raw.body.len(), 4, "3 items + manifest");
    for r in &raw.body[..3] {
        assert_eq!(get(r, "t").unwrap().as_text(), Some("item"));
        assert_eq!(bytes_of(get(r, "nonce").unwrap()).len(), 24);
        assert!(is_canonical(r));
    }
    assert_eq!(get(&raw.body[3], "t").unwrap().as_text(), Some("manifest"), "manifest is the last record");
    let mut body_enc = Vec::new();
    ciborium::into_writer(&Value::Array(raw.body.clone()), &mut body_enc).unwrap();
    assert_eq!(body_enc, raw.body_bytes, "body canonical, no trailing bytes");
}

/// 01 §2-§4: keys, AADs, HKDF labels, manifest sorted by id, ItemPlain shape; checked with an
/// independent implementation.
#[test]
fn f02_independent_crypto_opens_file() {
    let (mut v, ids) = sample(5);
    v.delete(ids[0], 9_000).unwrap();
    let b = v.serialize();
    let o = indep::open_file(&b, PW);
    assert_eq!(o.items.len(), 5);
    let pairs: Vec<(Vec<u8>, u64)> = o
        .manifest
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let a = p.as_array().unwrap();
            (bytes_of(&a[0]), u64_of(&a[1]))
        })
        .collect();
    let mut want: Vec<(Vec<u8>, u64)> = o.items.iter().map(|(i, m, _)| (i.clone(), *m)).collect();
    want.sort();
    assert_eq!(pairs, want, "01 §4 manifest = (id, modified_at) sorted by id");
    for (_, ma, pt) in &o.items {
        assert!(is_canonical(pt), "ItemPlain canonical CBOR");
        assert!(get(pt, "kind").is_none(), "01 §4: writers omit item kind (removed 2026-10-30)");
        for k in ["title", "deleted_at", "device_id", "favorite", "tags", "fields"] {
            assert!(get(pt, k).is_some(), "ItemPlain key {k}");
        }
        assert_eq!(bytes_of(get(pt, "device_id").unwrap()).len(), 16);
        // 01 §4: item modified_at = max(field.modified_at, deleted_at, metadata change)
        let mut mx = 0;
        for f in get(pt, "fields").unwrap().as_array().unwrap() {
            mx = mx.max(u64_of(get(f, "modified_at").unwrap()));
            let kind = get(f, "kind").unwrap().as_text().unwrap();
            assert!(["text", "password", "totp", "url", "notes", "email", "date", "month_year", "section"].contains(&kind));
            // 01 §4 Field.id "required in version 2": bytes(16), random v4
            let fid = bytes_of(get(f, "id").expect("01 §4: v2 field carries id"));
            assert_eq!(fid.len(), 16, "field id is bytes(16)");
            assert_eq!(fid[6] >> 4, 4, "Field::new id is a random v4 UUID");
        }
        if let Some(Value::Integer(d)) = get(pt, "deleted_at") {
            let d: i128 = (*d).into();
            mx = mx.max(d as u64);
        }
        assert!(*ma >= mx, "item modified_at {ma} < max field/deleted stamp {mx}");
    }
}

/// 01 §1: parsers reject wrong magic, format_version > SUPPORTED, header_len beyond EOF,
/// trailing bytes after the body array.
#[test]
fn f03_parser_rejections() {
    let (v, _) = sample(1);
    let b = v.serialize();
    let mut m = b.clone();
    m[0] = b'X';
    assert!(matches!(LockedVault::parse(&m), Err(VaultError::BadMagic)));
    let mut m = b.clone();
    m[4..6].copy_from_slice(&3u16.to_be_bytes());
    assert!(matches!(LockedVault::parse(&m), Err(VaultError::UnsupportedVersion(3))));
    let mut m = b.clone();
    m[6..10].copy_from_slice(&(b.len() as u32).to_be_bytes());
    assert!(LockedVault::parse(&m).is_err(), "header_len beyond EOF");
    let mut m = b.clone();
    m[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(LockedVault::parse(&m).is_err(), "header_len u32::MAX");
    let mut m = b.clone();
    m.push(0);
    assert!(LockedVault::parse(&m).is_err(), "trailing byte after body");
    let mut m = b.clone();
    m.extend_from_slice(&[0x80]);
    assert!(LockedVault::parse(&m).is_err(), "trailing empty CBOR array");
    assert!(LockedVault::parse(&[]).is_err());
    assert!(LockedVault::parse(b"RVLT").is_err());
    // version 0 is not "> SUPPORTED"; whatever happens must not panic.
    let mut m = b.clone();
    m[4..6].copy_from_slice(&0u16.to_be_bytes());
    let _ = LockedVault::parse(&m).and_then(|l| l.unlock(&pw(PW)));
}

/// 02 guarantee 4: flipping any byte in any item ct -> Tampered(Item(id)).
#[test]
fn f04_item_ct_flip_every_byte() {
    let (v, _) = sample(2);
    let b = v.serialize();
    let raw = split(&b);
    for idx in 0..2 {
        let rec = &raw.body[idx];
        let id = Uuid::from_slice(&bytes_of(get(rec, "id").unwrap())).unwrap();
        let ct = bytes_of(get(rec, "ct").unwrap());
        for pos in 0..ct.len() {
            let mut body = raw.body.clone();
            let mut c = ct.clone();
            c[pos] ^= 0x01;
            set(&mut body[idx], "ct", Value::Bytes(c));
            let f = join(raw.version, &raw.header, &body);
            match unlock(&f) {
                Err(VaultError::Tampered(TamperKind::Item(x))) if x == id => {}
                other => panic!("item {idx} ct byte {pos}: {:?}", other.err()),
            }
        }
    }
}

/// 02 guarantee 4 variant: the item nonce and the plaintext modified_at are in the AEAD.
#[test]
fn f05_item_nonce_and_modified_at_bound() {
    let (v, _) = sample(1);
    let b = v.serialize();
    let raw = split(&b);
    let mut body = raw.body.clone();
    let mut n = bytes_of(get(&body[0], "nonce").unwrap());
    n[0] ^= 1;
    set(&mut body[0], "nonce", Value::Bytes(n));
    assert!(matches!(unlock(&join(raw.version, &raw.header, &body)), Err(VaultError::Tampered(TamperKind::Item(_)))));
    let mut body = raw.body.clone();
    let ma = u64_of(get(&body[0], "modified_at").unwrap());
    set(&mut body[0], "modified_at", Value::Integer((ma + 1).into()));
    let r = unlock(&join(raw.version, &raw.header, &body));
    assert!(matches!(r, Err(VaultError::Tampered(_))), "{:?}", r.err());
}

/// 02 guarantee 5 and 6, and 01 §4 "duplicating items".
#[test]
fn f06_drop_rollback_duplicate_reorder() {
    let (mut v, ids) = sample(3);
    let old = v.serialize();
    v.set_field_named(ids[1], "password", pw("new"), 50_000).unwrap();
    let new = v.serialize();
    let rn = split(&new);
    let ro = split(&old);
    // drop
    let mut body = rn.body.clone();
    body.remove(0);
    assert!(matches!(unlock(&join(rn.version, &rn.header, &body)), Err(VaultError::Tampered(TamperKind::Manifest))), "drop");
    // rollback item 1 to old record (find by id)
    let idb = ids[1].as_bytes().to_vec();
    let pos_new = rn.body.iter().position(|r| get(r, "id").map(bytes_of) == Some(idb.clone())).unwrap();
    let old_rec = ro.body.iter().find(|r| get(r, "id").map(bytes_of) == Some(idb.clone())).unwrap().clone();
    let mut body = rn.body.clone();
    body[pos_new] = old_rec;
    assert!(matches!(unlock(&join(rn.version, &rn.header, &body)), Err(VaultError::Tampered(TamperKind::Manifest))), "rollback");
    // duplicate
    let mut body = rn.body.clone();
    let d = body[0].clone();
    body.insert(0, d);
    let r = unlock(&join(rn.version, &rn.header, &body));
    assert!(matches!(r, Err(VaultError::Tampered(_)) | Err(VaultError::Malformed(_))), "duplicate: {:?}", r.err());
    // swap manifests between serializations of the same vault: still valid (same content) -> must unlock
    let mut body = rn.body.clone();
    let n = body.len();
    let rn2 = split(&v.serialize());
    body[n - 1] = rn2.body[n - 1].clone();
    assert!(unlock(&join(rn.version, &rn.header, &body)).is_ok(), "manifest from another serialize of same state");
    // whole-file rollback (old file) is a valid older file: accepted by design.
    assert!(unlock(&old).is_ok());
    // manifest not last
    let mut body = rn.body.clone();
    let m = body.pop().unwrap();
    body.insert(0, m);
    assert!(unlock(&join(rn.version, &rn.header, &body)).is_err(), "manifest not last");
    // no manifest
    let mut body = rn.body.clone();
    body.pop();
    assert!(unlock(&join(rn.version, &rn.header, &body)).is_err(), "no manifest");
    // two manifests
    let mut body = rn.body.clone();
    let m = body.last().unwrap().clone();
    body.push(m);
    assert!(unlock(&join(rn.version, &rn.header, &body)).is_err(), "two manifests");
}

/// 02 guarantee 7: moving an item record into a different vault -> Tampered(Item(id)).
#[test]
fn f07_swap_item_into_other_vault() {
    let (a, ids) = sample(1);
    let (b, _) = sample(1);
    let ra = split(&a.serialize());
    let rb = split(&b.serialize());
    let mut body = rb.body.clone();
    body.insert(0, ra.body[0].clone());
    match unlock(&join(rb.version, &rb.header, &body)) {
        Err(VaultError::Tampered(TamperKind::Item(x))) => assert_eq!(x, ids[0]),
        o => panic!("{:?}", o.err()),
    }
    // replace instead of insert (count unchanged)
    let mut body = rb.body.clone();
    body[0] = ra.body[0].clone();
    assert!(matches!(unlock(&join(rb.version, &rb.header, &body)), Err(VaultError::Tampered(TamperKind::Item(_)))));
}

/// 01 §2: tampering with vault_id fails every slot; KDF tamper -> WrongPassword;
/// header structural damage -> not Ok.
#[test]
fn f08_header_tamper() {
    let (v, _) = sample(1);
    let b = v.serialize();
    let raw = split(&b);
    let mut h = raw.header.clone();
    let mut id = bytes_of(get(&h, "vault_id").unwrap());
    id[3] ^= 0x40;
    set(&mut h, "vault_id", Value::Bytes(id));
    assert!(matches!(unlock(&join(raw.version, &h, &raw.body)), Err(VaultError::WrongPassword)), "vault_id tamper");
    let mut h = raw.header.clone();
    set(get_mut(&mut h, "kdf").unwrap(), "t_cost", Value::Integer(2.into()));
    assert!(matches!(unlock(&join(raw.version, &h, &raw.body)), Err(VaultError::WrongPassword)), "kdf tamper");
    let mut h = raw.header.clone();
    let mut salt = bytes_of(get(get(&h, "kdf").unwrap(), "salt").unwrap());
    salt[0] ^= 1;
    set(get_mut(&mut h, "kdf").unwrap(), "salt", Value::Bytes(salt));
    assert!(matches!(unlock(&join(raw.version, &h, &raw.body)), Err(VaultError::WrongPassword)), "salt tamper");
    // every byte of the header region flipped: never Ok with different items, never panic
    let orig = snap_vault(&unlock(&b).unwrap());
    for pos in 4..(10 + raw.header_len as usize) {
        let mut m = b.clone();
        m[pos] ^= 0x01;
        let r = with_timeout(30, move || std::panic::catch_unwind(|| unlock(&m).map(|u| snap_vault(&u))).map_err(|_| ()));
        match r {
            None => panic!("header byte {pos}: unlock did not finish in 30 s"),
            Some(Err(())) => panic!("header byte {pos}: panic"),
            Some(Ok(Ok(s))) => assert_eq!(s, orig, "header byte {pos}: accepted with different items"),
            Some(Ok(Err(_))) => {}
        }
    }
}

/// 02 guarantee 3 / 01 §7: wrong password -> WrongPassword.
#[test]
fn f09_wrong_password() {
    let (v, _) = sample(1);
    let l = LockedVault::parse(&v.serialize()).unwrap();
    assert!(matches!(l.unlock(&pw("correct horse battery stapl")), Err(VaultError::WrongPassword)));
    assert!(matches!(l.unlock(&pw("")), Err(VaultError::WrongPassword)));
}

/// 02 guarantee 1 and 2; Phase-1 acceptance "create -> add 100 items -> serialize -> parse -> unlock -> equal".
#[test]
fn f10_round_trip_100_and_fresh_nonces() {
    let (v, _) = sample(100);
    let a = v.serialize();
    let b = v.serialize();
    assert_ne!(a, b, "two serialize calls differ (nonces)");
    let ua = unlock(&a).unwrap();
    let ub = unlock(&b).unwrap();
    assert_eq!(snap_vault(&ua), snap_vault(&v));
    assert_eq!(snap_vault(&ub), snap_vault(&v));
    // 01 §5: nonces fresh across records and across calls
    let mut seen = std::collections::HashSet::new();
    for f in [&a, &b] {
        let r = split(f);
        for s in get(&r.header, "slots").unwrap().as_array().unwrap() {
            let _ = s;
        }
        for rec in &r.body {
            assert!(seen.insert(bytes_of(get(rec, "nonce").unwrap())), "nonce reused");
        }
    }
    // item_summaries: plaintext metadata only, matches records
    let l = LockedVault::parse(&a).unwrap();
    assert_eq!(l.item_summaries().count(), 100);
}

/// 01 §2 "password is NFC-normalised before hashing".
#[test]
fn f11_nfc_password() {
    let composed = "caf\u{e9} na\u{ef}ve r\u{e9}sum\u{e9} 12";
    let decomposed = "cafe\u{301} nai\u{308}ve re\u{301}sume\u{301} 12";
    let v = UnlockedVault::create(&pw(decomposed), KdfParams::for_tests(), Uuid::new_v4());
    let b = v.serialize();
    LockedVault::parse(&b).unwrap().unlock(&pw(composed)).expect("NFC: composed opens decomposed-created vault");
    // and the independent KEK uses the NFC form
    indep::open_file(&b, composed);
}

/// 01 §4 + 02 Field: a TOTP/password value survives byte-exact (Unicode, empty, long).
#[test]
fn f12_values_round_trip_exact() {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(PW), KdfParams::for_tests(), dev);
    let vals = ["", " leading", "trailing ", "line\nbreak", "\u{0}nul", "emoji \u{1F512}", &"x".repeat(100_000)];
    let mut it = Item::new("", dev, 5);
    for (i, s) in vals.iter().enumerate() {
        it.fields.push(Field::new(format!("f{i}"), FieldKind::Text, pw(s), 5));
    }
    let id = v.insert(it, 5);
    let u = unlock(&v.serialize()).unwrap();
    let got = u.get(id).unwrap();
    for (i, s) in vals.iter().enumerate() {
        let f = got.fields.iter().find(|f| f.name == format!("f{i}")).unwrap();
        assert_eq!(f.value.expose_secret(), s);
    }
}

/// 01 §8 fixtures, opened with the current reader (§9 "every fixture ... opens").
#[test]
fn f13_spec_fixtures_open() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/vault-core/tests/fixtures");
    let basic = std::fs::read(dir.join("v1-basic.vault")).expect("01 §8 v1-basic.vault committed");
    let u = unlock(&basic).unwrap();
    assert_eq!(u.items().count(), 3, "v1-basic: 3 items");
    let empty = std::fs::read(dir.join("v1-empty.vault")).expect("01 §8 v1-empty.vault committed");
    assert_eq!(unlock(&empty).unwrap().items().count(), 0);
    let kdf = LockedVault::parse(&basic).unwrap().kdf_params().clone();
    assert_eq!((kdf.m_cost_kib, kdf.t_cost, kdf.p_cost), (8192, 1, 1), "01 §8 fixed KDF m=8192,t=1,p=1");
    for name in ["v1-attach.vault", "v1-stamped.vault", "v1-forward.vault"] {
        let b = std::fs::read(dir.join(name)).unwrap_or_else(|_| panic!("{name} committed (01 §4/§9)"));
        unlock(&b).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        indep::open_file(&b, PW);
    }
}

/// 01 §9 forward compatibility on v1-forward.vault: unknown keys at every level, opaque slot,
/// unknown item and field kinds survive a read-write cycle (compared on decrypted CBOR).
#[test]
fn f14_forward_fixture_preserved() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/vault-core/tests/fixtures");
    let b = std::fs::read(dir.join("v1-forward.vault")).unwrap();
    let before = indep::open_file(&b, PW);
    let rb = split(&b);
    let u = unlock(&b).unwrap();
    let out = u.serialize();
    let after = indep::open_file(&out, PW);
    let ra = split(&out);
    // header: every key except volatile ones preserved; slots incl. opaque preserved verbatim
    let hb = &rb.header;
    let ha = &ra.header;
    if let Value::Map(e) = hb {
        for (k, val) in e {
            let k = k.as_text().unwrap_or("?");
            assert_eq!(get(ha, k), Some(val), "header key {k} preserved");
        }
    }
    let kinds: Vec<_> = get(hb, "slots").unwrap().as_array().unwrap().iter().map(|s| get(s, "kind").unwrap().clone()).collect();
    assert!(kinds.iter().any(|k| !["password", "enclave", "passkey", "recovery"].contains(&k.as_text().unwrap())), "fixture has an opaque slot");
    // items: plaintext maps identical, except (rewritten 2026-10-31 for 01 §9) that a version 1
    // file "merely gains explicit ids" on save: every field gains exactly an `id` key.
    assert_eq!(rb.version, ra.version, "01 §9: a save never changes a file's version");
    assert_eq!(before.items.len(), after.items.len());
    for (id, _, pt) in &before.items {
        let a = after.items.iter().find(|(i, _, _)| i == id).unwrap();
        let mut want = pt.clone();
        let mut got = a.2.clone();
        for m in [&mut want, &mut got] {
            if let Some(Value::Array(fs)) = get_mut(m, "fields") {
                for f in fs.iter_mut() {
                    if let Value::Map(e) = f {
                        e.retain(|(k, _)| k.as_text() != Some("id"));
                    }
                }
            }
        }
        assert_eq!(got, want, "ItemPlain preserved verbatim on re-serialize (apart from field ids)");
        for f in get(&a.2, "fields").unwrap().as_array().unwrap() {
            assert_eq!(bytes_of(get(f, "id").expect("v1 file gains explicit field ids on save")).len(), 16);
        }
    }
    // unknown keys on item records / manifest record
    for (i, rec) in rb.body.iter().enumerate() {
        if let Value::Map(e) = rec {
            for (k, val) in e {
                let k = k.as_text().unwrap_or("?");
                if ["nonce", "ct"].contains(&k) {
                    continue;
                }
                let same = ra.body.iter().any(|r| get(r, k) == Some(val));
                assert!(same, "record {i} key {k} preserved");
            }
        }
    }
    // unknown field kinds are sensitive (02: is_sensitive = Password | Totp | Other)
    for it in u.items_including_deleted() {
        for f in &it.fields {
            if f.kind_raw.is_some() {
                assert!(f.kind.is_sensitive(), "unknown field kind is sensitive");
            }
        }
    }
}

/// 01 §2: opaque slot kinds; NoUsableSlot from plaintext; kind strings exact; duplicate ids Malformed.
#[test]
fn f15_slot_kinds() {
    let (v, _) = sample(1);
    let b = v.serialize();
    let raw = split(&b);
    // only slot gets an unknown kind -> NoUsableSlot, and before Argon2 even with hostile m_cost
    let mut h = raw.header.clone();
    if let Some(Value::Array(slots)) = get_mut(&mut h, "slots") {
        set(&mut slots[0], "kind", Value::Text("Password".into()));
    }
    set(get_mut(&mut h, "kdf").unwrap(), "m_cost", Value::Integer((1u32 << 20).into()));
    let f = join(raw.version, &h, &raw.body);
    let t = std::time::Instant::now();
    let r = with_timeout(20, move || LockedVault::parse(&f).and_then(|l| l.unlock(&pw(PW))).err());
    assert!(matches!(r, Some(Some(VaultError::NoUsableSlot))), "case-sensitive kind -> NoUsableSlot: {r:?}");
    assert!(t.elapsed().as_secs() < 5, "NoUsableSlot decided before Argon2");
    // opaque slot alongside password slot: unlocks, and is re-emitted verbatim in position.
    // Built on an unstamped file (v1-empty.vault): on a stamped header a spliced slot is
    // Tampered(Manifest) by design (01 §4 header_digest), checked in f18.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/vault-core/tests/fixtures");
    let unstamped = std::fs::read(dir.join("v1-empty.vault")).unwrap();
    let ru = split(&unstamped);
    assert!(get(&ru.header, "slots_modified_at").is_none(), "v1-empty.vault is unstamped");
    let mut h = ru.header.clone();
    let opaque = Value::Map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![9; 16])),
        (Value::Text("kind".into()), Value::Text("hwkey".into())),
        (Value::Text("zz_extra".into()), Value::Array(vec![Value::Integer(1.into())])),
    ]);
    if let Some(Value::Array(slots)) = get_mut(&mut h, "slots") {
        slots.insert(0, opaque.clone());
    }
    let f = join(ru.version, &h, &ru.body);
    let u = unlock(&f).expect("opaque slot is skipped at unlock");
    let out = split(&u.serialize());
    assert_eq!(get(&out.header, "slots").unwrap().as_array().unwrap()[0], opaque, "opaque slot re-emitted in original position");
    // duplicate slot ids -> Malformed
    let mut h = raw.header.clone();
    if let Some(Value::Array(slots)) = get_mut(&mut h, "slots") {
        let s = slots[0].clone();
        slots.push(s);
    }
    let r = LockedVault::parse(&join(raw.version, &h, &raw.body)).and_then(|l| l.unlock(&pw(PW)));
    assert!(matches!(r, Err(VaultError::Malformed(_))), "duplicate slot id: {:?}", r.err());
    // zero slots: "at least one"
    let mut h = raw.header.clone();
    set(&mut h, "slots", Value::Array(vec![]));
    assert!(LockedVault::parse(&join(raw.version, &h, &raw.body)).and_then(|l| l.unlock(&pw(PW))).is_err());
}

/// Hostile KDF parameters (01 §2 kdf map; 01 §6 calibration caps m_cost at 1 GiB): parse or
/// unlock must refuse or finish quickly; never hang, abort, or allocate unbounded memory.
#[test]
fn f16_hostile_kdf_params() {
    let (v, _) = sample(1);
    let raw = split(&v.serialize());
    let cases: Vec<(&str, Value)> = vec![
        ("m_cost", Value::Integer(u32::MAX.into())),
        ("m_cost", Value::Integer((u64::MAX).into())),
        ("m_cost", Value::Integer(0.into())),
        ("m_cost", Value::Integer(7.into())),
        ("m_cost", Value::Integer((-1).into())),
        ("m_cost", Value::Integer((4u64 << 20).into())), // 4 GiB
        ("t_cost", Value::Integer(0.into())),
        ("t_cost", Value::Integer(u32::MAX.into())),
        ("t_cost", Value::Integer(100_000.into())),
        ("p_cost", Value::Integer(0.into())),
        ("p_cost", Value::Integer(u32::MAX.into())),
        ("p_cost", Value::Integer(1_000_000.into())),
        ("salt", Value::Bytes(vec![])),
        ("salt", Value::Bytes(vec![1; 31])),
        ("salt", Value::Bytes(vec![1; 100_000])),
        ("alg", Value::Text("argon2i".into())),
        ("alg", Value::Text("ARGON2ID".into())),
        ("alg", Value::Integer(1.into())),
        ("m_cost", Value::Text("8192".into())),
    ];
    let mut report = vec![];
    for (k, val) in cases {
        let mut h = raw.header.clone();
        set(get_mut(&mut h, "kdf").unwrap(), k, val.clone());
        let f = join(raw.version, &h, &raw.body);
        let t = std::time::Instant::now();
        let r = with_timeout(15, move || {
            std::panic::catch_unwind(|| LockedVault::parse(&f).and_then(|l| l.unlock(&pw(PW))).map(|_| ()))
                .map_err(|_| "panic")
        });
        let desc = format!("{k}={val:?}: {:?} in {:?}", r.as_ref().map(|x| x.as_ref().map(|y| y.as_ref().err())), t.elapsed());
        match r {
            None => report.push(format!("HANG {desc}")),
            Some(Err(_)) => report.push(format!("PANIC {desc}")),
            Some(Ok(Ok(()))) => report.push(format!("ACCEPTED {desc}")),
            Some(Ok(Err(_))) => {
                if t.elapsed().as_secs() >= 5 {
                    report.push(format!("SLOW {desc}"))
                }
            }
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}

/// 01 §4/§9: editing an item from v1-forward (set_field on an unknown-kind field, title change,
/// merge between two devices) keeps kind_raw and every unknown key at item and field level.
#[test]
fn f17_forward_preserved_through_edit_and_merge() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/vault-core/tests/fixtures");
    let b = std::fs::read(dir.join("v1-forward.vault")).unwrap();
    let before = indep::open_file(&b, PW);
    let l = LockedVault::parse(&b).unwrap();
    let mut a = l.unlock(&pw(PW)).unwrap();
    let mut other = l.unlock_with_key(&a.export_vault_key(), Uuid::new_v4()).unwrap();
    let mut touched = vec![];
    let ids: Vec<Uuid> = a.items_including_deleted().map(|i| i.id).collect();
    for id in &ids {
        let it = a.items_including_deleted().find(|i| i.id == *id).unwrap();
        if let Some(f) = it.fields.iter().find(|f| f.kind_raw.is_some()) {
            let name = f.name.clone();
            a.set_field_named(*id, &name, pw("edited-on-old-reader"), 9_000_000_000_000).unwrap();
            touched.push((*id, name));
        }
        other.update(*id, 9_000_000_000_001, |i| i.title = format!("{} (b)", i.title)).unwrap();
    }
    assert!(!touched.is_empty(), "fixture has an unknown-kind field");
    let theirs = LockedVault::parse(&other.serialize()).unwrap().unlock_with_key(&a.export_vault_key(), a.device_id()).unwrap();
    a.merge_from(&theirs).unwrap();
    let after = indep::open_file(&a.serialize(), PW);
    let keys = |m: &Value| -> Vec<String> {
        match m {
            Value::Map(e) => e.iter().filter_map(|(k, _)| k.as_text().map(String::from)).collect(),
            _ => vec![],
        }
    };
    for (id, _, pt) in &before.items {
        let a2 = &after.items.iter().find(|(i, _, _)| i == id).unwrap().2;
        for k in keys(pt) {
            assert!(get(a2, &k).is_some(), "item key {k} lost after edit+merge");
        }
        let fb = get(pt, "fields").unwrap().as_array().unwrap();
        let fa = get(a2, "fields").unwrap().as_array().unwrap();
        for f in fb {
            let name = get(f, "name").unwrap();
            let g = fa.iter().find(|x| get(x, "name") == Some(name)).unwrap_or_else(|| panic!("field {name:?} lost"));
            assert_eq!(get(g, "kind"), get(f, "kind"), "field kind string preserved for {name:?}");
            for k in keys(f) {
                assert!(get(g, &k).is_some(), "field key {k} lost on {name:?}");
            }
        }
    }
}

/// 01 §2/§4 (spec update 2026-10-30): every new vault is stamped, so splicing any slot into its
/// header (opaque, password-shaped, enclave-shaped; at the start or the end) fails the manifest's
/// header_digest -> Tampered(Manifest) on every unlock path (password, kek, key).
#[test]
fn f18_slot_splice_into_stamped_vault_is_tampered() {
    let (mut v, _) = sample(1);
    let kek = secrecy::SecretVec::new(vec![4u8; 32]);
    let sid = v.add_enclave_slot(&kek, 50_000);
    let b = v.serialize();
    let raw = split(&b);
    assert!(get(&raw.header, "slots_modified_at").is_some(), "01 §2: new vault carries slots_modified_at");
    let slots = get(&raw.header, "slots").unwrap().as_array().unwrap().clone();
    let mut pw_copy = slots.iter().find(|s| get(s, "kind").unwrap().as_text() == Some("password")).unwrap().clone();
    set(&mut pw_copy, "id", Value::Bytes(vec![0xA1; 16]));
    let mut en_copy = slots.iter().find(|s| get(s, "kind").unwrap().as_text() == Some("enclave")).unwrap().clone();
    set(&mut en_copy, "id", Value::Bytes(vec![0xA2; 16]));
    let opaque = Value::Map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![0xA3; 16])),
        (Value::Text("kind".into()), Value::Text("hwkey".into())),
    ]);
    let key = v.export_vault_key();
    let mut bad = vec![];
    for (name, slot) in [("opaque", opaque), ("password-shaped", pw_copy), ("enclave-shaped", en_copy)] {
        for at_start in [true, false] {
            let mut h = raw.header.clone();
            if let Some(Value::Array(s)) = get_mut(&mut h, "slots") {
                if at_start { s.insert(0, slot.clone()) } else { s.push(slot.clone()) }
            }
            let f = join(raw.version, &h, &raw.body);
            let l = LockedVault::parse(&f).unwrap();
            let r1 = l.unlock(&pw(PW)).err();
            let r2 = l.unlock_with_kek(sid, &kek).err();
            let r3 = l.unlock_with_key(&key, Uuid::new_v4()).err();
            for (path, r) in [("password", r1), ("kek", r2), ("key", r3)] {
                if !matches!(r, Some(VaultError::Tampered(TamperKind::Manifest))) {
                    bad.push(format!("{name} at_start={at_start} via {path}: {r:?}"));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
