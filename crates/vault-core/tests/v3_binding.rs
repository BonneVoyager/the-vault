//! Format version 3 (security review 2026-11-26 I-04, 01 §4): every plaintext byte of the
//! file is authenticated. The manifest AAD's `header_digest` covers the whole header map
//! (`created_at` and unknown header keys included) plus the manifest record's own unknown
//! keys, and each manifest entry carries a digest of its item record's unknown plaintext
//! keys. A by-hand edit anywhere in the plaintext is therefore `Tampered(Manifest)` (header,
//! manifest record) or `Tampered(Item(id))` (item record). Version 1 and 2 files keep the
//! v1.1 binding until `upgrade_format` moves them to 3.

mod common;

use ciborium::Value;
use common::*;
use vault_core::format::{PLAINTEXT_BINDING_VERSION, VaultFile};
use vault_core::{
    ExposeSecret, FORMAT_VERSION, KdfParams, LockedVault, TamperKind, UnlockedVault, Uuid,
    VaultError,
};

const V2_BASIC: &[u8] = include_bytes!("fixtures/v2-basic.vault");
const V3_BASIC: &[u8] = include_bytes!("fixtures/v3-basic.vault");
const V3_META: &[u8] = include_bytes!("fixtures/v3-meta.vault");
const V1_FORWARD: &[u8] = include_bytes!("fixtures/v1-forward.vault");

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn manifest() -> VaultError {
    VaultError::Tampered(TamperKind::Manifest)
}

fn item(id: Uuid) -> VaultError {
    VaultError::Tampered(TamperKind::Item(id))
}

/// A fresh (version 3) vault with three items, saved.
fn fresh_v3_bytes() -> Vec<u8> {
    let mut v = new_vault();
    populate(&mut v, 3);
    let bytes = v.serialize();
    assert_eq!(&bytes[4..6], &[0, 3]);
    bytes
}

#[test]
fn version_constants() {
    assert_eq!(FORMAT_VERSION, 3);
    assert_eq!(PLAINTEXT_BINDING_VERSION, 3);
    assert_eq!(new_vault().header().format_version, 3);
}

#[test]
fn tampered_header_created_at_is_tampered_manifest() {
    for (name, bytes) in [
        ("fresh", fresh_v3_bytes()),
        ("v3-basic", V3_BASIC.to_vec()),
        ("v3-meta", V3_META.to_vec()),
    ] {
        let original = VaultFile::parse(&bytes).unwrap().header.created_at;
        for edit in [original + 1, original.saturating_sub(1), 0, u64::MAX] {
            if edit == original {
                continue;
            }
            let tampered = rewrite(&bytes, |f| f.header.created_at = edit);
            assert_eq!(
                VaultFile::parse(&tampered).unwrap().header.created_at,
                edit,
                "{name}: the edit is in the plaintext"
            );
            assert_eq!(unlock(&tampered).unwrap_err(), manifest(), "{name}: {edit}");
        }
    }
}

#[test]
fn injected_altered_or_removed_unknown_header_key_is_tampered_manifest() {
    for (name, bytes) in [
        ("fresh", fresh_v3_bytes()),
        ("v3-basic", V3_BASIC.to_vec()),
        ("v3-meta", V3_META.to_vec()),
    ] {
        let injected = rewrite(&bytes, |f| {
            f.header.extras.push((t("x_injected"), t("evil")))
        });
        assert_eq!(unlock(&injected).unwrap_err(), manifest(), "{name}: inject");
        // Unknown keys inside `kdf` and on the known slot are bound too (they were under
        // v1.1 already; still true).
        let kdf = rewrite(&bytes, |f| {
            f.header.kdf_extras.push((t("x_kdf2"), Value::Null))
        });
        assert_eq!(unlock(&kdf).unwrap_err(), manifest(), "{name}: kdf");
        let slot = rewrite(&bytes, |f| {
            f.header.slots[0]
                .as_key_mut()
                .unwrap()
                .extras
                .push((t("x_slot2"), Value::Null));
        });
        assert_eq!(unlock(&slot).unwrap_err(), manifest(), "{name}: slot");
    }
    // `v3-meta` carries an unknown header key: altering or removing it is caught as well.
    let file = VaultFile::parse(V3_META).unwrap();
    assert_eq!(file.header.extras.len(), 1);
    let altered = rewrite(V3_META, |f| f.header.extras[0].1 = t("changed"));
    assert_eq!(unlock(&altered).unwrap_err(), manifest(), "alter");
    let removed = rewrite(V3_META, |f| f.header.extras.clear());
    assert_eq!(unlock(&removed).unwrap_err(), manifest(), "remove");
    // The unknown key is kept through a save by this build (01 §9).
    let reopened = unlock(V3_META).unwrap();
    let saved = VaultFile::parse(&reopened.serialize()).unwrap();
    assert_eq!(saved.header.extras, file.header.extras);
}

#[test]
fn stripping_or_moving_the_header_stamp_in_a_v3_file_is_tampered_manifest() {
    let bytes = fresh_v3_bytes();
    let stripped = rewrite(&bytes, |f| {
        f.header.slots_modified_at = None;
        f.header.slots_device_id = None;
    });
    assert!(
        VaultFile::parse(&stripped)
            .unwrap()
            .header
            .digest()
            .is_some(),
        "version 3 is digest-bound even without a stamp, so the strip cannot evade the check"
    );
    assert_eq!(unlock(&stripped).unwrap_err(), manifest());
    let raised = rewrite(&bytes, |f| {
        f.header.slots_modified_at = Some(f.header.slots_modified_at.unwrap() + 1);
    });
    assert_eq!(unlock(&raised).unwrap_err(), manifest());
    let other_device = rewrite(&bytes, |f| f.header.slots_device_id = Some(Uuid::nil()));
    assert_eq!(unlock(&other_device).unwrap_err(), manifest());
}

#[test]
fn injected_unknown_item_record_key_is_tampered_item_naming_that_record() {
    for (name, bytes) in [("fresh", fresh_v3_bytes()), ("v3-basic", V3_BASIC.to_vec())] {
        let file = VaultFile::parse(&bytes).unwrap();
        assert!(file.items.len() >= 2);
        assert!(file.items.iter().all(|r| r.extras.is_empty()));
        for idx in 0..file.items.len() {
            let id = file.items[idx].id;
            let injected = rewrite(&bytes, |f| {
                f.items[idx]
                    .extras
                    .push((t("x_record_injected"), Value::Bytes(vec![0xEE])));
            });
            // The record's own tag still verifies (extras are outside the item AAD); the
            // manifest's digest is what names the record.
            assert_eq!(
                unlock(&injected).unwrap_err(),
                item(id),
                "{name}: item {idx}"
            );
        }
        // Two records tampered: the first in id order is reported (records are id-sorted
        // on disk, so that is the first record).
        let both = rewrite(&bytes, |f| {
            for r in f.items.iter_mut() {
                r.extras.push((t("x"), Value::Null));
            }
        });
        assert_eq!(
            unlock(&both).unwrap_err(),
            item(file.items[0].id),
            "{name}: both"
        );
    }
}

#[test]
fn altered_or_removed_unknown_item_record_key_is_tampered_item() {
    let file = VaultFile::parse(V3_META).unwrap();
    assert_eq!(file.items.len(), 1);
    let id = file.items[0].id;
    assert_eq!(
        file.items[0].extras.len(),
        1,
        "v3-meta carries a record extra"
    );
    assert!(unlock(V3_META).is_ok(), "the committed bytes verify");

    let altered_value = rewrite(V3_META, |f| f.items[0].extras[0].1 = Value::Bytes(vec![0]));
    assert_eq!(unlock(&altered_value).unwrap_err(), item(id), "value");
    let renamed_key = rewrite(V3_META, |f| f.items[0].extras[0].0 = t("x_renamed"));
    assert_eq!(unlock(&renamed_key).unwrap_err(), item(id), "key");
    let removed = rewrite(V3_META, |f| f.items[0].extras.clear());
    assert_eq!(unlock(&removed).unwrap_err(), item(id), "removed");
    let added = rewrite(V3_META, |f| {
        f.items[0].extras.push((t("x_second"), Value::Null))
    });
    assert_eq!(unlock(&added).unwrap_err(), item(id), "second key");

    // A dropped record is still Manifest (the pair check runs first), and a flipped
    // ciphertext byte is still the record's own tag failure (02 guarantee 4).
    let bytes = fresh_v3_bytes();
    let file = VaultFile::parse(&bytes).unwrap();
    let dropped = rewrite(&bytes, |f| {
        f.items.remove(1);
    });
    assert_eq!(unlock(&dropped).unwrap_err(), manifest());
    let flipped = rewrite(&bytes, |f| {
        f.items[1].ct[0] ^= 1;
        f.items[1].extras.push((t("x"), Value::Null));
    });
    assert_eq!(unlock(&flipped).unwrap_err(), item(file.items[1].id));
}

#[test]
fn injected_altered_or_removed_unknown_manifest_record_key_is_tampered_manifest() {
    for (name, bytes) in [("fresh", fresh_v3_bytes()), ("v3-basic", V3_BASIC.to_vec())] {
        let injected = rewrite(&bytes, |f| {
            f.manifest.extras.push((t("x_man"), Value::Null))
        });
        assert_eq!(unlock(&injected).unwrap_err(), manifest(), "{name}");
    }
    let file = VaultFile::parse(V3_META).unwrap();
    assert_eq!(
        file.manifest.extras.len(),
        1,
        "v3-meta carries a manifest extra"
    );
    let altered = rewrite(V3_META, |f| f.manifest.extras[0].1 = Value::Bool(true));
    assert_eq!(unlock(&altered).unwrap_err(), manifest(), "alter");
    let removed = rewrite(V3_META, |f| f.manifest.extras.clear());
    assert_eq!(unlock(&removed).unwrap_err(), manifest(), "remove");
}

/// The same edits on the `unlock_with_key` path (vault-sync's watcher): identical verdicts
/// on a vault with items; an empty vault keeps the documented `WrongPassword` residual.
#[cfg(feature = "sync")]
#[test]
fn key_path_reports_the_same_tamper_kinds() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let key = v.export_vault_key();
    let bytes = v.serialize();
    let open = |b: &[u8]| {
        LockedVault::parse(b)
            .unwrap()
            .unlock_with_key(&key, device())
    };
    assert!(open(&bytes).is_ok());
    let id = VaultFile::parse(&bytes).unwrap().items[1].id;
    let created = rewrite(&bytes, |f| f.header.created_at += 1);
    assert_eq!(open(&created).unwrap_err(), manifest());
    let header_key = rewrite(&bytes, |f| f.header.extras.push((t("x"), Value::Null)));
    assert_eq!(open(&header_key).unwrap_err(), manifest());
    let record_key = rewrite(&bytes, |f| f.items[1].extras.push((t("x"), Value::Null)));
    assert_eq!(open(&record_key).unwrap_err(), item(id));
    let manifest_key = rewrite(&bytes, |f| f.manifest.extras.push((t("x"), Value::Null)));
    assert_eq!(open(&manifest_key).unwrap_err(), manifest());
    // Prefix downgrade on the key path: every AAD binds the version, so the first item
    // record fails before anything authenticated; the probe then opens the manifest under
    // the relabelled version's AAD, which fails too, and the 2026-11-21 L1 rule maps
    // "nothing authenticates under this key" to `WrongPassword` (vault-sync re-verifies
    // with the password, which is `WrongPassword` as well, see below).
    for version in [2u16, 1] {
        let downgraded = with_prefix_version(&bytes, version);
        assert_eq!(
            open(&downgraded).unwrap_err(),
            VaultError::WrongPassword,
            "key path, relabelled {version}"
        );
    }

    let empty = new_vault();
    let key = empty.export_vault_key();
    let bytes = empty.serialize();
    let created = rewrite(&bytes, |f| f.header.created_at += 1);
    assert_eq!(
        LockedVault::parse(&created)
            .unwrap()
            .unlock_with_key(&key, device())
            .unwrap_err(),
        VaultError::WrongPassword,
        "empty vault: the manifest is the only tag check (documented residual)"
    );
    assert_eq!(
        unlock(&created).unwrap_err(),
        manifest(),
        "password path names it"
    );
}

/// A version 3 file with its prefix relabelled as 2 or 1 (the only way to downgrade a file
/// by hand). It parses (both are supported versions) but nothing opens: the slot AAD binds
/// the version, so the password path is `WrongPassword` (01 §7: a slot tag failure on a
/// cleanly parsed header is never `Tampered`), and so is `unlock_with_kek`.
fn with_prefix_version(bytes: &[u8], version: u16) -> Vec<u8> {
    let mut b = bytes.to_vec();
    b[4..6].copy_from_slice(&version.to_be_bytes());
    b
}

#[test]
fn prefix_downgrade_of_a_v3_file_opens_nothing() {
    for (name, bytes) in [
        ("fresh", fresh_v3_bytes()),
        ("v3-basic", V3_BASIC.to_vec()),
        ("v3-meta", V3_META.to_vec()),
        ("empty", new_vault().serialize()),
    ] {
        for version in [2u16, 1] {
            let downgraded = with_prefix_version(&bytes, version);
            let locked = LockedVault::parse(&downgraded)
                .unwrap_or_else(|e| panic!("{name} as {version}: {e}"));
            assert_eq!(locked.header().format_version, version);
            assert_eq!(
                locked.unlock(&pw()).unwrap_err(),
                VaultError::WrongPassword,
                "{name} relabelled {version}: password path"
            );
        }
    }
    // The genuine prefix still opens, and a relabel to a newer version is refused.
    assert!(unlock(V3_BASIC).is_ok());
    assert_eq!(
        LockedVault::parse(&with_prefix_version(V3_BASIC, 4)).unwrap_err(),
        VaultError::UnsupportedVersion(4)
    );
}

/// A version 2 file reads and saves exactly as before (version 2, v1.1 binding, so the
/// header `created_at` and record-level unknown keys are *not* yet bound), and
/// `upgrade_format` is what moves it to 3 and closes that.
#[test]
fn v2_fixture_unlocks_saves_as_v2_and_upgrades_to_v3() {
    let v2 = unlock(V2_BASIC).unwrap();
    assert_eq!(v2.header().format_version, 2);
    let saved = v2.serialize();
    assert_eq!(&saved[4..6], &[0, 2], "a plain save keeps version 2");
    let reopened = unlock(&saved).unwrap();
    assert_vaults_eq(&v2, &reopened);
    assert_eq!(reopened.header(), v2.header());

    // Under version 2 only kdf/slots/stamp are bound: these edits still open (the hole).
    let hole_created = rewrite(&saved, |f| f.header.created_at += 1);
    assert!(unlock(&hole_created).is_ok(), "v2: created_at unbound");
    let hole_record = rewrite(&saved, |f| f.items[0].extras.push((t("x"), Value::Null)));
    assert!(unlock(&hole_record).is_ok(), "v2: record keys unbound");
    let bound_slot = rewrite(&saved, |f| f.header.kdf_extras.push((t("x"), Value::Null)));
    assert_eq!(
        unlock(&bound_slot).unwrap_err(),
        manifest(),
        "v2: kdf bound (v1.1)"
    );

    // The upgrade: same items, same key, version 3, everything bound.
    let mut up = unlock(&saved).unwrap();
    up.set_device_id(device());
    let before_stamp = up.header().slots_stamp();
    up.upgrade_format(&pw(), before_stamp + 10).unwrap();
    assert_eq!(up.header().format_version, 3);
    assert_eq!(up.header().slots_modified_at, Some(before_stamp + 10));
    let v3 = up.serialize();
    assert_eq!(&v3[4..6], &[0, 3]);
    let re = unlock(&v3).unwrap();
    assert_eq!(re.header().format_version, 3);
    assert_vaults_eq(&v2, &re);
    assert_eq!(re.header().created_at, v2.header().created_at);
    let closed_created = rewrite(&v3, |f| f.header.created_at += 1);
    assert_eq!(
        unlock(&closed_created).unwrap_err(),
        manifest(),
        "v3: bound"
    );
    let id = VaultFile::parse(&v3).unwrap().items[0].id;
    let closed_record = rewrite(&v3, |f| f.items[0].extras.push((t("x"), Value::Null)));
    assert_eq!(unlock(&closed_record).unwrap_err(), item(id), "v3: bound");
    // Idempotent: already at 3.
    assert_eq!(up.upgrade_format(&secret("whatever"), 1), Ok(()));
    assert_eq!(up.header().slots_modified_at, Some(before_stamp + 10));
}

/// Version 1: a plain save of an unstamped legacy file stamps it with 1 (L-02) but keeps
/// version 1 and its binding; the v1-forward unknown keys survive the upgrade to 3 (that
/// is how `v3-meta.vault` was built) and are then bound.
#[test]
fn v1_forward_stays_v1_on_a_plain_save_and_its_unknown_keys_are_bound_after_upgrade() {
    let v1 = unlock(V1_FORWARD).unwrap();
    assert_eq!(v1.header().format_version, 1);
    let saved = v1.serialize();
    assert_eq!(&saved[4..6], &[0, 1]);
    let file = VaultFile::parse(&saved).unwrap();
    assert_eq!(
        file.header.slots_modified_at,
        Some(1),
        "L-02 first-save stamp"
    );
    assert_eq!(file.items[0].extras.len(), 1);
    let hole = rewrite(&saved, |f| f.items[0].extras[0].1 = Value::Null);
    assert!(unlock(&hole).is_ok(), "v1: record keys unbound");

    let mut up = unlock(&saved).unwrap();
    up.set_device_id(device());
    up.upgrade_format(&pw(), 5_000).unwrap();
    let v3 = up.serialize();
    assert_eq!(&v3[4..6], &[0, 3]);
    let f3 = VaultFile::parse(&v3).unwrap();
    assert_eq!(f3.header.extras, file.header.extras, "header extra kept");
    assert_eq!(f3.header.kdf_extras, file.header.kdf_extras);
    assert_eq!(
        f3.items[0].extras, file.items[0].extras,
        "record extra kept"
    );
    assert_eq!(
        f3.manifest.extras, file.manifest.extras,
        "manifest extra kept"
    );
    assert_eq!(
        f3.header.slots.len(),
        1,
        "opaque slot dropped by the upgrade"
    );
    let re = unlock(&v3).unwrap();
    assert_vaults_eq(&v1, &re);
    let id = f3.items[0].id;
    let closed = rewrite(&v3, |f| f.items[0].extras[0].1 = Value::Null);
    assert_eq!(unlock(&closed).unwrap_err(), item(id));
    let closed = rewrite(&v3, |f| f.manifest.extras.clear());
    assert_eq!(unlock(&closed).unwrap_err(), manifest());
}

/// Header merge: unknown header keys travel with the winning header (whole header = one
/// unit under version 3); the loser's are replaced, ours are kept when ours wins. The
/// merged file verifies because the writer recomputes every digest.
#[test]
fn header_extras_travel_with_the_winning_header_and_the_merged_file_verifies() {
    let mut a = new_vault();
    populate(&mut a, 1);
    a.header_extras_mut().push((t("x_from_a"), t("a")));
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(Uuid::from_u128(0xB));
    assert_eq!(b.header().extras, vec![(t("x_from_a"), t("a"))]);

    // B makes a slot change with a newer stamp and a different unknown key.
    let newer = a.header().slots_stamp() + 100;
    b.change_password(&pw(), &pw(), KdfParams::for_tests(), newer)
        .unwrap();
    b.header_extras_mut().clear();
    b.header_extras_mut().push((t("x_from_b"), t("b")));
    let b_snap = unlock(&b.serialize()).unwrap();
    assert_eq!(b_snap.header().extras, vec![(t("x_from_b"), t("b"))]);

    let report = a.merge_from(&b_snap).unwrap();
    assert!(report.header_updated);
    assert_eq!(
        a.header().extras,
        vec![(t("x_from_b"), t("b"))],
        "theirs won: theirs' keys"
    );
    assert_eq!(a.header().slots_modified_at, Some(newer));
    assert_eq!(a.header().created_at, b_snap.header().created_at);
    let merged = a.serialize();
    let re = unlock(&merged).unwrap();
    assert_eq!(re.header(), a.header());

    // The other way round: B merging the (now identical-header) A keeps its own.
    let a_snap = unlock(&merged).unwrap();
    assert!(!b.merge_from(&a_snap).unwrap().header_updated);
    assert_eq!(b.header().extras, vec![(t("x_from_b"), t("b"))]);

    // Ours wins (older peer): our keys stay.
    let mut c: UnlockedVault = unlock(&merged).unwrap();
    c.set_device_id(device());
    c.header_extras_mut().push((t("x_from_c"), t("c")));
    let older = unlock(&a.serialize()).unwrap();
    assert!(!c.merge_from(&older).unwrap().header_updated);
    assert_eq!(
        c.header().extras,
        vec![(t("x_from_b"), t("b")), (t("x_from_c"), t("c"))]
    );
    assert!(unlock(&c.serialize()).is_ok());
}

/// A record-level unknown key read from a version 3 file survives every kind of save
/// (the digest is recomputed from memory) and is dropped with the record it belonged to.
#[test]
fn record_extras_survive_saves_and_mutations_under_v3() {
    let mut v = unlock(V3_META).unwrap();
    v.set_device_id(device());
    let id = v.items().next().unwrap().id;
    v.set_field_named(id, "username", secret("edited"), T_EDIT)
        .unwrap();
    let saved = v.serialize();
    let file = VaultFile::parse(&saved).unwrap();
    assert_eq!(
        file.items[0].extras.len(),
        1,
        "record extra kept across an edit"
    );
    let re = unlock(&saved).unwrap();
    assert_eq!(
        re.get(id)
            .unwrap()
            .field("username")
            .unwrap()
            .value
            .expose_secret(),
        "edited"
    );
    // `delete_permanently` strips the record's unknown keys with its content; the file
    // still verifies (absent digest == no keys).
    let mut re = re;
    re.set_device_id(device());
    re.delete(id, T_EDIT + 1).unwrap();
    re.delete_permanently(id, T_EDIT + 2).unwrap();
    let stripped = re.serialize();
    assert!(
        VaultFile::parse(&stripped).unwrap().items[0]
            .extras
            .is_empty()
    );
    assert!(unlock(&stripped).is_ok());
}

const T_EDIT: u64 = 1_800_000_000_000;
