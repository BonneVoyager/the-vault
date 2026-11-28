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

/// How many unknown keys a file carries at the four plaintext sites outside the item
/// records: `[header, kdf map, first key slot, manifest record]`.
fn unknown_key_sites(file: &VaultFile) -> [usize; 4] {
    let slot = file.header.slots.iter().find_map(|s| s.as_key()).unwrap();
    [
        file.header.extras.len(),
        file.header.kdf_extras.len(),
        slot.extras.len(),
        file.manifest.extras.len(),
    ]
}

fn one_key(name: &str) -> Vec<(Value, Value)> {
    vec![(t(name), Value::Integer(7.into()))]
}

fn assert_opens_on_both_paths(bytes: &[u8], v: &UnlockedVault) {
    assert_vaults_eq(&unlock(bytes).unwrap(), v);
    #[cfg(feature = "sync")]
    LockedVault::parse(bytes)
        .unwrap()
        .unlock_with_key(&v.export_vault_key(), device())
        .unwrap();
}

fn evil_anywhere(file: &VaultFile) -> bool {
    let evil = |keys: &[(Value, Value)]| keys.iter().any(|(k, _)| k.as_text() == Some("evil"));
    evil(&file.header.extras)
        || evil(&file.header.kdf_extras)
        || evil(&file.manifest.extras)
        || file
            .header
            .slots
            .iter()
            .any(|s| s.as_key().is_some_and(|k| evil(&k.extras)))
        || file.items.iter().any(|r| evil(&r.extras))
}

/// `bytes` (below version 3) with `evil` at all five plaintext sites. On an unstamped file
/// a plain edit does it; a stamped one has its kdf and slot maps under the v1.1 digest, so
/// those two are written the way a blind first save binds them: by a key holder.
fn evil_everywhere(bytes: &[u8]) -> Vec<u8> {
    let stamped = VaultFile::parse(bytes)
        .unwrap()
        .header
        .slots_modified_at
        .is_some();
    let maps = |f: &mut VaultFile| {
        f.header.kdf_extras = one_key("evil");
        let slot = f.header.slots.iter_mut().find_map(|s| s.as_key_mut());
        slot.unwrap().extras = one_key("evil");
    };
    let bytes = if stamped {
        rewrite_with_key(bytes, maps)
    } else {
        rewrite(bytes, maps)
    };
    rewrite(&bytes, |f| {
        f.header.extras = one_key("evil");
        f.manifest.extras = one_key("evil");
        for rec in &mut f.items {
            rec.extras = one_key("evil");
        }
    })
}

/// Version 1: a plain save of an unstamped legacy file stamps it with 1 (L-02) but keeps
/// version 1, its binding and every unknown key. The upgrade to 3 binds every plaintext
/// key from then on, so it drops every unknown key of the old file instead of vouching
/// for it (owner decisions 2026-11-27): header, kdf map, slot map, item record, manifest
/// record. That holds after the first save too: the stamp that save wrote puts the kdf
/// and slot maps under the v1.1 digest, but it stamped them as they were read, so it says
/// nothing about who chose their keys. (`v3-meta.vault` was built by this upgrade before
/// those decisions and carries all of them, bound.)
#[test]
fn v1_forward_stays_v1_on_a_plain_save_and_the_upgrade_drops_every_unknown_key() {
    let v1 = unlock(V1_FORWARD).unwrap();
    assert_eq!(v1.header().format_version, 1);
    assert_eq!(v1.header().slots_modified_at, None, "unstamped fixture");
    let saved = v1.serialize();
    assert_eq!(&saved[4..6], &[0, 1]);
    let file = VaultFile::parse(&saved).unwrap();
    assert_eq!(
        file.header.slots_modified_at,
        Some(1),
        "L-02 first-save stamp"
    );
    assert_eq!(unknown_key_sites(&file), [1, 1, 1, 1], "a save keeps all");
    assert_eq!(file.items[0].extras.len(), 1);
    let hole = rewrite(&saved, |f| f.items[0].extras[0].1 = Value::Null);
    assert!(unlock(&hole).is_ok(), "v1: record keys unbound");

    // Straight from the unstamped file, and from the file its first save stamped.
    for (name, bytes) in [("unstamped", V1_FORWARD), ("first save", saved.as_slice())] {
        let mut up = unlock(bytes).unwrap();
        up.set_device_id(device());
        up.upgrade_format(&pw(), 5_000).unwrap();
        let v3 = up.serialize();
        assert_eq!(&v3[4..6], &[0, 3], "{name}");
        let f3 = VaultFile::parse(&v3).unwrap();
        assert_eq!(unknown_key_sites(&f3), [0, 0, 0, 0], "{name}");
        assert!(f3.items[0].extras.is_empty(), "{name}");
        assert_eq!(f3.header.slots.len(), 1, "{name}: opaque slot dropped too");
        assert_eq!(f3.header.vault_id, file.header.vault_id);
        assert_eq!(f3.header.created_at, file.header.created_at, "known key");
        assert_vaults_eq(&v1, &unlock(&v3).unwrap());
        assert_opens_on_both_paths(&v3, &up);
        // Version 3 binds what is left: none of the dropped keys can be put back by hand.
        let id = f3.items[0].id;
        let closed = rewrite(&v3, |f| f.items[0].extras = file.items[0].extras.clone());
        assert_eq!(unlock(&closed).unwrap_err(), item(id), "{name}");
        let closed = rewrite(&v3, |f| f.header.extras = file.header.extras.clone());
        assert_eq!(unlock(&closed).unwrap_err(), manifest(), "{name}");
        let closed = rewrite(&v3, |f| {
            f.header.kdf_extras = file.header.kdf_extras.clone()
        });
        assert_eq!(unlock(&closed).unwrap_err(), manifest(), "{name}");
        let closed = rewrite(&v3, |f| f.manifest.extras = file.manifest.extras.clone());
        assert_eq!(unlock(&closed).unwrap_err(), manifest(), "{name}");
    }
}

/// The version 2 fixture has a stamped header, so its kdf and slot maps are under the v1.1
/// digest and only a holder of the vault key can write unknown keys into them. The upgrade
/// drops those as well, with the keys planted at the sites version 2 binds to nothing: a
/// pre-3 stamp can come from a blind first save, so it does not make a key trustworthy.
/// The upgraded file opens on both paths and the version 3 tamper map holds on it.
#[test]
fn upgrade_from_a_stamped_v2_header_drops_every_unknown_key_too() {
    let stamp = unlock(V2_BASIC).unwrap().header().slots_modified_at;
    assert!(stamp.is_some(), "stamped fixture");
    let planted = evil_everywhere(V2_BASIC);
    let before = VaultFile::parse(&planted).unwrap();
    assert_eq!(unknown_key_sites(&before), [1, 1, 1, 1]);
    assert!(before.items.iter().all(|r| r.extras.len() == 1));
    let mut v = unlock(&planted).unwrap();
    v.set_device_id(device());
    assert_eq!(v.header().format_version, 2);

    v.upgrade_format(&pw(), stamp.unwrap() + 10).unwrap();
    let v3 = v.serialize();
    assert_eq!(&v3[4..6], &[0, 3]);
    let f3 = VaultFile::parse(&v3).unwrap();
    assert!(!evil_anywhere(&f3));
    assert_eq!(unknown_key_sites(&f3), [0, 0, 0, 0]);
    assert_opens_on_both_paths(&v3, &v);

    let tampered = rewrite(&v3, |f| f.header.extras = one_key("evil"));
    assert_eq!(unlock(&tampered).unwrap_err(), manifest());
    let tampered = rewrite(&v3, |f| f.header.kdf_extras = one_key("evil"));
    assert_eq!(unlock(&tampered).unwrap_err(), manifest());
    let tampered = rewrite(&v3, |f| f.manifest.extras = one_key("evil"));
    assert_eq!(unlock(&tampered).unwrap_err(), manifest());
}

/// Security review 2026-11-27, round 3. `v1-basic` is unstamped; keys are planted at all
/// five sites without the vault key. Whatever a key holder does before the upgrade (a
/// save and a fresh unlock by password or by key, a password change, a key rotation, an
/// enclave enrolment: each of them stamps the header with the planted kdf and slot keys
/// inside the digest), the version 3 file the upgrade leads to carries none of them and
/// opens on both paths.
#[test]
fn no_step_before_the_upgrade_gets_a_planted_key_into_a_v3_file() {
    const V1_BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
    let planted = evil_everywhere(V1_BASIC);
    let before = VaultFile::parse(&planted).unwrap();
    assert_eq!(before.header.slots_modified_at, None, "unstamped fixture");
    assert_eq!(unknown_key_sites(&before), [1, 1, 1, 1]);
    assert!(!before.items.is_empty() && before.items.iter().all(|r| r.extras.len() == 1));

    type Step = fn(UnlockedVault) -> UnlockedVault;
    let steps: [(&str, Step); 5] = [
        ("save, unlock by password", |v| {
            unlock(&v.serialize()).unwrap()
        }),
        ("save, unlock by key", |v| {
            #[cfg(feature = "sync")]
            let v = LockedVault::parse(&v.serialize())
                .unwrap()
                .unlock_with_key(&v.export_vault_key(), device())
                .unwrap();
            v
        }),
        ("change_password", |mut v| {
            v.change_password(&pw(), &pw(), KdfParams::for_tests(), 50)
                .unwrap();
            v
        }),
        ("rotate_vault_key", |mut v| {
            v.rotate_vault_key(&pw(), 50).unwrap();
            v
        }),
        ("add_enclave_slot", |mut v| {
            v.add_enclave_slot(&vault_core::SecretVec::new(vec![7; 32]), 50);
            v
        }),
    ];
    for (name, step) in steps {
        let mut v = step(unlock(&planted).unwrap());
        v.set_device_id(device());
        let stamped = VaultFile::parse(&v.serialize()).unwrap();
        assert_eq!(stamped.header.format_version, 1, "{name}");
        assert!(stamped.header.slots_modified_at.is_some(), "{name}");
        assert!(evil_anywhere(&stamped), "{name}: still there below 3");

        v.upgrade_format(&pw(), 5_000).unwrap();
        let v3 = v.serialize();
        assert_eq!(&v3[4..6], &[0, 3], "{name}");
        let f3 = VaultFile::parse(&v3).unwrap();
        assert!(!evil_anywhere(&f3), "{name}");
        assert_eq!(unknown_key_sites(&f3), [0, 0, 0, 0], "{name}");
        assert!(f3.items.iter().all(|r| r.extras.is_empty()), "{name}");
        assert_opens_on_both_paths(&v3, &v);
    }
}

/// A pre-3 header stamp cannot be forged, extended or removed without the vault key
/// (01 §4, v1.1 digest), on either unlock path: adding `slots_modified_at` to an
/// unstamped file (with or without a kdf or slot key planted alongside), and planting a
/// kdf or slot key in, or stripping the stamp from, a stamped version 1 or 2 file are all
/// `Tampered(Manifest)`. (The password path of several of these is also covered by
/// `header_merge.rs::stamped_header_is_bound_into_the_manifest`, `legacy_header.rs::
/// legacy_file_is_stamped_by_its_first_save_and_the_manifest_then_covers_the_slots` and
/// the `v1-stamped` fixture test; this adds the key path, the slot map, version 2 and the
/// self-stamp variants.) So the only way planted kdf or slot keys end up under a stamp is
/// a key holder's own blind save, which is why the upgrade does not trust the stamp.
#[test]
fn a_pre_v3_header_stamp_cannot_be_added_stripped_or_extended_without_the_key() {
    const V1_BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
    type Edit = fn(&mut VaultFile);
    let kdf_key: Edit = |f| f.header.kdf_extras = one_key("evil");
    let slot_key: Edit = |f| {
        let slot = f.header.slots.iter_mut().find_map(|s| s.as_key_mut());
        slot.unwrap().extras = one_key("evil");
    };
    let nothing: Edit = |_| {};
    let assert_rejected = |original: &[u8], tampered: &[u8], what: &str| {
        assert_eq!(unlock(tampered).unwrap_err(), manifest(), "{what}");
        #[cfg(feature = "sync")]
        assert_eq!(
            LockedVault::parse(tampered)
                .unwrap()
                .unlock_with_key(&unlock(original).unwrap().export_vault_key(), device())
                .unwrap_err(),
            manifest(),
            "{what}: key path"
        );
        let _ = original;
    };

    // Self-stamping an unstamped file.
    assert_eq!(
        VaultFile::parse(V1_BASIC).unwrap().header.slots_modified_at,
        None
    );
    for stamp in [1, 9_000_000_000_000, u64::MAX] {
        for device_id in [None, Some(device())] {
            for (plant_name, plant) in [("no key", nothing), ("kdf", kdf_key), ("slot", slot_key)] {
                let tampered = rewrite(V1_BASIC, |f| {
                    f.header.slots_modified_at = Some(stamp);
                    f.header.slots_device_id = device_id;
                    plant(f);
                });
                let what = format!("self-stamp {stamp} {device_id:?} {plant_name}");
                assert_rejected(V1_BASIC, &tampered, &what);
            }
        }
    }

    // A stamped version 1 file (the first save of the fixture) and the version 2 fixture.
    let v1_stamped = unlock(V1_BASIC).unwrap().serialize();
    for (name, stamped) in [("v1", v1_stamped.as_slice()), ("v2", V2_BASIC)] {
        assert!(
            VaultFile::parse(stamped)
                .unwrap()
                .header
                .slots_modified_at
                .is_some()
        );
        let strip: Edit = |f| {
            f.header.slots_modified_at = None;
            f.header.slots_device_id = None;
        };
        for (edit_name, edit) in [
            ("kdf key", kdf_key),
            ("slot key", slot_key),
            ("strip", strip),
        ] {
            let tampered = rewrite(stamped, edit);
            assert_rejected(stamped, &tampered, &format!("{name} {edit_name}"));
        }
    }
}

/// The merge route to version 3. Ours is below 3 with keys planted in the header's top
/// level and in the manifest record; the peer is at 3 with bound keys of its own at both
/// sites. The header merge adopts the peer's header whole, its unknown keys included, and
/// ours' manifest-record keys are dropped: they are not merged by any rule, so the vault
/// then has none (not the peer's). Nothing moves afterwards in either direction.
#[test]
fn adopting_a_v3_header_takes_the_peer_header_keys_and_drops_our_manifest_record_keys() {
    for (name, snapshot) in [("v1", unstamped_bytes()), ("v2", V2_BASIC)] {
        let planted = rewrite(snapshot, |f| {
            f.header.extras = one_key("evil");
            f.manifest.extras = one_key("evil");
        });
        let mut ours = unlock(&planted).unwrap();
        ours.set_device_id(device());
        assert_eq!(ours.header().extras, one_key("evil"), "{name}");

        let mut peer = unlock(snapshot).unwrap();
        peer.set_device_id(Uuid::from_u128(0xB));
        peer.upgrade_format(&pw(), 9_000_000_000_000).unwrap();
        let peer_bytes = rewrite_with_key(&peer.serialize(), |f| {
            f.header.extras = one_key("x_peer");
            f.manifest.extras = one_key("x_peer");
        });
        let mut peer = unlock(&peer_bytes).unwrap();
        peer.set_device_id(Uuid::from_u128(0xB));

        let report = ours.merge_from(&peer).unwrap();
        assert!(report.header_updated, "{name}");
        let saved = ours.serialize();
        assert_eq!(&saved[4..6], &[0, 3], "{name}");
        let file = VaultFile::parse(&saved).unwrap();
        assert_eq!(file.header.extras, one_key("x_peer"), "{name}");
        assert!(file.manifest.extras.is_empty(), "{name}");
        assert_opens_on_both_paths(&saved, &ours);

        assert!(!peer.merge_from(&unlock(&saved).unwrap()).unwrap().changed());
        let peer_file = VaultFile::parse(&peer.serialize()).unwrap();
        assert_eq!(peer_file.manifest.extras, one_key("x_peer"), "{name}");
        assert!(!ours.merge_from(&peer).unwrap().changed(), "{name}");
        let again = VaultFile::parse(&ours.serialize()).unwrap();
        assert!(again.manifest.extras.is_empty(), "{name}");
    }
}

/// A vault already at version 3 keeps every unknown key (they are all bound) through a
/// no-op `upgrade_format` and a merge with its own copy.
#[test]
fn a_v3_vault_keeps_every_unknown_key_through_a_no_op_upgrade_and_a_self_merge() {
    let before = VaultFile::parse(V3_META).unwrap();
    assert_eq!(unknown_key_sites(&before), [1, 1, 1, 1]);
    assert_eq!(before.items[0].extras.len(), 1);
    let mut v = unlock(V3_META).unwrap();
    v.set_device_id(device());
    v.upgrade_format(&pw(), 9_000_000_000_000).unwrap();
    assert!(!v.merge_from(&unlock(V3_META).unwrap()).unwrap().changed());
    let saved = v.serialize();
    let after = VaultFile::parse(&saved).unwrap();
    assert_eq!(after.header, before.header);
    assert_eq!(after.manifest.extras, before.manifest.extras);
    assert_eq!(after.items[0].extras, before.items[0].extras);
    assert!(unlock(&saved).is_ok());
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
