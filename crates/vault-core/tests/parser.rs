//! Parser rejections (01 §1) and structural rules (01 §4).

mod common;

use ciborium::Value;
use common::*;
use vault_core::format::{PREFIX_LEN, VaultFile};
use vault_core::{LockedVault, VaultError};

fn parse(bytes: &[u8]) -> Result<LockedVault, VaultError> {
    LockedVault::parse(bytes)
}

fn good() -> Vec<u8> {
    let mut v = new_vault();
    populate(&mut v, 2);
    v.serialize()
}

fn header_len(bytes: &[u8]) -> usize {
    u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize
}

#[test]
fn bad_magic() {
    let mut b = good();
    b[0] = b'X';
    assert_eq!(parse(&b).unwrap_err(), VaultError::BadMagic);
    assert_eq!(parse(b"KDBX").unwrap_err(), VaultError::BadMagic);
    assert_eq!(parse(b"").unwrap_err(), VaultError::Truncated);
    assert_eq!(parse(b"RV").unwrap_err(), VaultError::Truncated);
}

#[test]
fn unsupported_version() {
    let mut b = good();
    b[4] = 0;
    b[5] = 3;
    assert_eq!(parse(&b).unwrap_err(), VaultError::UnsupportedVersion(3));
    b[4] = 0xFF;
    assert_eq!(
        parse(&b).unwrap_err(),
        VaultError::UnsupportedVersion(0xFF03)
    );
    // Version 0 never existed; the AADs bind the prefix version so it must be rejected early.
    b[4] = 0;
    b[5] = 0;
    assert_eq!(parse(&b).unwrap_err(), VaultError::UnsupportedVersion(0));
}

#[test]
fn kdf_params_bounds_rejected_at_parse() {
    use vault_core::kdf::{MAX_M_COST_KIB, MAX_P_COST, MAX_T_COST};
    let b = good();
    type Edit = fn(&mut vault_core::KdfParams);
    let cases: [(&str, Edit); 8] = [
        ("m_cost zero", |k| k.m_cost_kib = 0),
        ("m_cost > 1 GiB", |k| k.m_cost_kib = MAX_M_COST_KIB + 1),
        ("m_cost max u32", |k| k.m_cost_kib = u32::MAX),
        ("t_cost zero", |k| k.t_cost = 0),
        ("t_cost > 64", |k| k.t_cost = MAX_T_COST + 1),
        ("t_cost max u32", |k| k.t_cost = u32::MAX),
        ("p_cost zero", |k| k.p_cost = 0),
        ("p_cost > 64", |k| k.p_cost = MAX_P_COST + 1),
    ];
    for (name, edit) in cases {
        let t = rewrite(&b, |f| edit(&mut f.header.kdf));
        assert!(
            matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)),
            "{name} must be Malformed at parse time"
        );
    }
    // The bounds themselves are accepted at parse time (no KDF runs during parse).
    let t = rewrite(&b, |f| {
        f.header.kdf.m_cost_kib = MAX_M_COST_KIB;
        f.header.kdf.t_cost = MAX_T_COST;
        f.header.kdf.p_cost = MAX_P_COST;
    });
    assert!(parse(&t).is_ok());
}

#[test]
fn truncated() {
    let b = good();
    assert_eq!(
        parse(&b[..PREFIX_LEN - 1]).unwrap_err(),
        VaultError::Truncated
    );
    // header_len past EOF
    let mut t = b.clone();
    t[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(parse(&t).unwrap_err(), VaultError::Truncated);
    let mut t = b.clone();
    t[6..10].copy_from_slice(&((b.len() - PREFIX_LEN + 1) as u32).to_be_bytes());
    assert_eq!(parse(&t).unwrap_err(), VaultError::Truncated);
    // header_len exactly to EOF: header parses, body is empty bytes -> Malformed
    let mut t = b.clone();
    t[6..10].copy_from_slice(&((b.len() - PREFIX_LEN) as u32).to_be_bytes());
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));
    // cut inside the body
    assert!(matches!(
        parse(&b[..b.len() - 5]).unwrap_err(),
        VaultError::Malformed(_)
    ));
}

#[test]
fn trailing_bytes() {
    let mut b = good();
    b.push(0x00);
    assert!(matches!(parse(&b).unwrap_err(), VaultError::Malformed(_)));
    // trailing bytes inside the declared header region
    let mut b = good();
    let hl = header_len(&b);
    b.insert(PREFIX_LEN + hl, 0xF6); // CBOR null after the header map
    b[6..10].copy_from_slice(&((hl + 1) as u32).to_be_bytes());
    assert!(matches!(parse(&b).unwrap_err(), VaultError::Malformed(_)));
}

fn with_body(bytes: &[u8], body: Value) -> Vec<u8> {
    let hl = header_len(bytes);
    let mut out = bytes[..PREFIX_LEN + hl].to_vec();
    ciborium::into_writer(&body, &mut out).unwrap();
    out
}

#[test]
fn body_structure() {
    let b = good();
    let file = VaultFile::parse(&b).unwrap();
    let hl = header_len(&b);
    let body: Value = ciborium::from_reader(&b[PREFIX_LEN + hl..]).unwrap();
    let Value::Array(records) = body else {
        panic!()
    };
    assert_eq!(records.len(), 3);

    // empty body (no manifest)
    let t = with_body(&b, Value::Array(vec![]));
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));
    // body is not an array
    let t = with_body(&b, Value::Map(vec![]));
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));
    // manifest not last
    let t = with_body(
        &b,
        Value::Array(vec![
            records[2].clone(),
            records[0].clone(),
            records[1].clone(),
        ]),
    );
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));
    // two manifests
    let t = with_body(
        &b,
        Value::Array(vec![
            records[0].clone(),
            records[2].clone(),
            records[2].clone(),
        ]),
    );
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));
    // only items, no manifest
    let t = with_body(
        &b,
        Value::Array(vec![records[0].clone(), records[1].clone()]),
    );
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));
    // unknown record type
    let t = with_body(
        &b,
        Value::Array(vec![
            Value::Map(vec![(Value::Text("t".into()), Value::Text("blob".into()))]),
            records[2].clone(),
        ]),
    );
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));
    // duplicate key in a record
    let Value::Map(mut m) = records[2].clone() else {
        panic!()
    };
    m.push(m[0].clone());
    let t = with_body(&b, Value::Array(vec![Value::Map(m)]));
    assert!(matches!(parse(&t).unwrap_err(), VaultError::Malformed(_)));

    // Manifest-only body is valid (empty vault).
    let t = with_body(&b, Value::Array(vec![records[2].clone()]));
    let l = parse(&t).unwrap();
    assert_eq!(l.item_summaries().count(), 0);
    assert_eq!(l.vault_id(), file.header.vault_id);
    assert_eq!(l.kdf_params(), &file.header.kdf);
}

#[test]
fn header_structure() {
    let b = good();
    let hl = header_len(&b);
    let hv: Value = ciborium::from_reader(&b[PREFIX_LEN..PREFIX_LEN + hl]).unwrap();
    let Value::Map(entries) = hv else { panic!() };

    let rebuild = |entries: Vec<(Value, Value)>| -> Vec<u8> {
        let mut h = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut h).unwrap();
        let mut out = b[..PREFIX_LEN].to_vec();
        out[6..10].copy_from_slice(&(h.len() as u32).to_be_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&b[PREFIX_LEN + hl..]);
        out
    };

    // missing vault_id
    let e: Vec<_> = entries
        .iter()
        .filter(|(k, _)| k != &Value::Text("vault_id".into()))
        .cloned()
        .collect();
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
    // vault_id wrong length
    let e: Vec<_> = entries
        .iter()
        .map(|(k, v)| {
            if k == &Value::Text("vault_id".into()) {
                (k.clone(), Value::Bytes(vec![0; 15]))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
    // no slots
    let e: Vec<_> = entries
        .iter()
        .map(|(k, v)| {
            if k == &Value::Text("slots".into()) {
                (k.clone(), Value::Array(vec![]))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
    // header not a map
    let mut out = b[..PREFIX_LEN].to_vec();
    out[6..10].copy_from_slice(&1u32.to_be_bytes());
    out.push(0xF6);
    out.extend_from_slice(&b[PREFIX_LEN + hl..]);
    assert!(matches!(parse(&out).unwrap_err(), VaultError::Malformed(_)));
    // unknown extras inside kdf are fine
    let t = rewrite(&b, |f| {
        f.header
            .kdf_extras
            .push((Value::Text("x".into()), Value::Null));
    });
    assert!(parse(&t).is_ok());
    // unknown kdf alg is structural damage
    let e: Vec<_> = entries
        .iter()
        .map(|(k, v)| {
            if k == &Value::Text("kdf".into()) {
                let Value::Map(kdf) = v else { panic!() };
                let kdf = kdf
                    .iter()
                    .map(|(kk, vv)| {
                        if kk == &Value::Text("alg".into()) {
                            (kk.clone(), Value::Text("scrypt".into()))
                        } else {
                            (kk.clone(), vv.clone())
                        }
                    })
                    .collect();
                (k.clone(), Value::Map(kdf))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
    // Rewrite the first slot's map through `edit`.
    type Entries = Vec<(Value, Value)>;
    let edit_slot0 = |edit: &dyn Fn(&mut Entries)| -> Entries {
        entries
            .iter()
            .map(|(k, v)| {
                if k == &Value::Text("slots".into()) {
                    let Value::Array(slots) = v else { panic!() };
                    let Value::Map(slot) = &slots[0] else {
                        panic!()
                    };
                    let mut slot = slot.clone();
                    edit(&mut slot);
                    (k.clone(), Value::Array(vec![Value::Map(slot)]))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    };
    // An unknown slot kind is NOT structural damage (01 §9 forward compatibility): the slot is
    // kept opaque; unlocking is then `NoUsableSlot` because no password slot is left.
    let e = edit_slot0(&|slot| {
        for (kk, vv) in slot.iter_mut() {
            if kk == &Value::Text("kind".into()) {
                *vv = Value::Text("yubikey".into());
            }
        }
    });
    let locked = parse(&rebuild(e)).expect("unknown slot kind is tolerated");
    assert_eq!(
        locked.slots().map(|(_, k)| k).collect::<Vec<_>>(),
        [vault_core::SlotKind::Other("yubikey".into())]
    );
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::NoUsableSlot);
    // ... but a slot whose `kind` is not text, or whose `id` is missing or mis-sized, still is,
    // even when the kind is unknown.
    let e = edit_slot0(&|slot| {
        for (kk, vv) in slot.iter_mut() {
            if kk == &Value::Text("kind".into()) {
                *vv = Value::Integer(7.into());
            }
        }
    });
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
    let e = edit_slot0(&|slot| {
        slot.retain(|(kk, _)| kk != &Value::Text("id".into()));
        for (kk, vv) in slot.iter_mut() {
            if kk == &Value::Text("kind".into()) {
                *vv = Value::Text("yubikey".into());
            }
        }
    });
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
    let e = edit_slot0(&|slot| {
        for (kk, vv) in slot.iter_mut() {
            if kk == &Value::Text("id".into()) {
                *vv = Value::Bytes(vec![0; 15]);
            } else if kk == &Value::Text("kind".into()) {
                *vv = Value::Text("yubikey".into());
            }
        }
    });
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
    // A known kind with a short wrapped_key is still structural damage.
    let e = edit_slot0(&|slot| {
        for (kk, vv) in slot.iter_mut() {
            if kk == &Value::Text("wrapped_key".into()) {
                *vv = Value::Bytes(vec![0; 47]);
            }
        }
    });
    assert!(matches!(
        parse(&rebuild(e)).unwrap_err(),
        VaultError::Malformed(_)
    ));
}

#[test]
fn format_roundtrip_is_lossless() {
    let b = good();
    let f = VaultFile::parse(&b).unwrap();
    assert_eq!(
        f.to_bytes(),
        b,
        "parse -> to_bytes is byte-identical (canonical)"
    );
}
