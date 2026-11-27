//! Format version 3: every plaintext byte is authenticated (security review 2026-11-26 I-04,
//! 01 §4 / §9). Added 2026-11-27. Each tamper is checked against vault-core and against the
//! independent opener in `src/lib.rs` (`indep::try_open_file`), which implements the v3 AAD
//! and digests from the spec without calling vault-core.
use spec_checks::*;
use uuid::Uuid;
use vault_core::*;

const FPW: &str = FIXTURE_PW;

/// A fresh core-made vault (current version) with one login item; returns (bytes, item id).
fn v3_with_item() -> (Vec<u8>, Uuid) {
    let dev = Uuid::new_v4();
    let mut v = UnlockedVault::create(&pw(FPW), KdfParams::for_tests(), dev);
    let mut it = Item::new("Bank".to_string(), dev, 1_000);
    it.fields.push(Field::new(
        "password",
        FieldKind::Password,
        pw("hunter2"),
        1_000,
    ));
    let id = v.insert(it, 1_000);
    let b = v.serialize();
    assert_eq!(version_of(&b), 3, "01 §9: new vaults are version 3");
    (b, id)
}

fn core_unlock(b: &[u8]) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(b).and_then(|l| l.unlock(&pw(FPW)))
}

/// Re-encodes a file with an edited (canonicalised) header, body untouched.
fn with_header(b: &[u8], f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let raw = split(b);
    let mut h = raw.header.clone();
    f(&mut h);
    join(raw.version, &canon(h), &raw.body)
}

/// Re-encodes a file with an edited (canonicalised) body.
fn with_body(b: &[u8], f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let raw = split(b);
    let mut body = raw.body.clone();
    f(&mut body);
    let body: Vec<Value> = body.into_iter().map(canon).collect();
    join(raw.version, &raw.header, &body)
}

fn assert_manifest_tamper(label: &str, b: &[u8]) {
    let r = core_unlock(b);
    assert!(
        matches!(r, Err(VaultError::Tampered(TamperKind::Manifest))),
        "{label}: core gave {:?}, want Tampered(Manifest)",
        r.err()
    );
    let r = indep::try_open_file(b, FPW);
    assert!(
        matches!(r, Err(indep::OpenError::Step(s)) if s.contains("manifest")),
        "{label}: independent opener did not fail the manifest step: {:?}",
        r.err()
    );
}

/// I-04: `created_at` is bound by the v3 header digest.
#[test]
fn bd01_created_at_tamper_is_manifest_tamper() {
    let (b, _) = v3_with_item();
    assert!(core_unlock(&b).is_ok());
    indep::open_file(&b, FPW);
    let ca = u64_of(get(&split(&b).header, "created_at").unwrap());
    let f = with_header(&b, |h| set(h, "created_at", i(ca + 1)));
    assert_ne!(f, b);
    assert_manifest_tamper("created_at + 1", &f);
}

/// I-04: an unknown header key (also inside `kdf`) is bound by the v3 header digest.
#[test]
fn bd02_unknown_header_key_injected_is_manifest_tamper() {
    let (b, _) = v3_with_item();
    let f = with_header(&b, |h| set(h, "x_injected", t("evil")));
    assert_manifest_tamper("header extra", &f);
    let f = with_header(&b, |h| {
        set(get_mut(h, "kdf").unwrap(), "x_injected", i(1));
    });
    assert_manifest_tamper("kdf extra", &f);
}

/// I-04: an unknown item-record key names the record: Tampered(Item(id)).
#[test]
fn bd03_unknown_item_record_key_injected_is_item_tamper() {
    let (b, id) = v3_with_item();
    let f = with_body(&b, |body| set(&mut body[0], "x_injected", t("evil")));
    let r = core_unlock(&f);
    assert!(
        matches!(r, Err(VaultError::Tampered(TamperKind::Item(x))) if x == id),
        "core gave {:?}, want Tampered(Item({id}))",
        r.err()
    );
    let r = indep::try_open_file(&f, FPW);
    assert_eq!(
        r.err(),
        Some(indep::OpenError::ItemExtras(id.as_bytes().to_vec())),
        "independent opener"
    );
}

/// I-04: an unknown manifest-record key is bound by the v3 manifest AAD.
#[test]
fn bd04_unknown_manifest_record_key_injected_is_manifest_tamper() {
    let (b, _) = v3_with_item();
    let f = with_body(&b, |body| {
        let m = body.last_mut().unwrap();
        set(m, "x_injected", Value::Null);
    });
    assert_manifest_tamper("manifest record extra", &f);
}

/// 01 §9: older files keep the v1.1 binding until upgraded (created_at is not bound in v2),
/// then `upgrade_format` moves them to version 3, they open in core and the independent
/// opener with the same content, and the same tamper is now caught.
#[test]
fn bd05_older_fixtures_unlock_and_upgrade_to_3() {
    let v2 = fixture("v2-basic.vault");
    assert_eq!(version_of(&v2), 2);
    let ca = u64_of(get(&split(&v2).header, "created_at").unwrap());
    let edited = with_header(&v2, |h| set(h, "created_at", i(ca + 1)));
    assert!(
        core_unlock(&edited).is_ok(),
        "v2: created_at is outside the v1.1 digest"
    );
    indep::open_file(&edited, FPW);

    for name in ["v1-basic.vault", "v2-basic.vault"] {
        let b = fixture(name);
        let mut v = core_unlock(&b).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let before = snap_vault(&v);
        let plain = v.serialize();
        assert_eq!(
            version_of(&plain),
            version_of(&b),
            "{name}: a save keeps the version"
        );
        v.upgrade_format(&pw(FPW), 1_900_000_000_000)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let out = v.serialize();
        assert_eq!(version_of(&out), 3, "{name}: upgraded to 3");
        let u = core_unlock(&out).unwrap_or_else(|e| panic!("{name} upgraded: {e:?}"));
        assert_eq!(snap_vault(&u), before, "{name}: content kept");
        let o = indep::open_file(&out, FPW);
        assert_eq!(o.items.len(), u.items_including_deleted().count(), "{name}");
        let ca = u64_of(get(&split(&out).header, "created_at").unwrap());
        let f = with_header(&out, |h| set(h, "created_at", i(ca + 1)));
        assert_manifest_tamper(&format!("{name} upgraded, created_at + 1"), &f);
    }
}

/// 01 §8: the committed v3 fixtures open with the independent opener (86-byte manifest AAD,
/// whole-header digest, entry digests) and agree with core on the item set.
#[test]
fn bd06_independent_opener_opens_v3_fixtures() {
    for name in ["v3-basic.vault", "v3-meta.vault"] {
        let b = fixture(name);
        assert_eq!(version_of(&b), 3, "{name}");
        let o = indep::open_file(&b, FPW);
        let u = core_unlock(&b).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let mut ours: Vec<Vec<u8>> = o.items.iter().map(|(id, _, _)| id.clone()).collect();
        ours.sort();
        let mut theirs: Vec<Vec<u8>> = u
            .items_including_deleted()
            .map(|i| i.id.as_bytes().to_vec())
            .collect();
        theirs.sort();
        assert_eq!(ours, theirs, "{name}: same item records");
        let entries = o.manifest.as_array().unwrap();
        assert_eq!(entries.len(), o.items.len(), "{name}: one entry per record");
        assert!(
            entries
                .iter()
                .all(|e| matches!(e.as_array().map(|a| a.len()), Some(2 | 3))),
            "{name}: entries are [id, modified_at(, digest)]"
        );
        let aad = indep::manifest_aad(
            &o.vault_id,
            o.items.len() as u32,
            3,
            Some(&[0; 32]),
            Some(&[0; 32]),
        );
        assert_eq!(aad.len(), 86, "01 §4: v3 manifest AAD is 86 bytes");
    }
}
