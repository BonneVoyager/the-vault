//! Header merge (03 §5 "Header merge", bug-hunt V-01/V-03): `header.slots_modified_at` and
//! `merge_from` taking the whole slot set + KDF params from the side with the greater stamp.

mod common;

use ciborium::Value;
use common::*;
use rand::RngCore;
use rand::rngs::OsRng;
use vault_core::format::VaultFile;
use vault_core::{
    ExposeSecret, KdfParams, LockedVault, OpaqueSlot, SecretString, SecretVec, Slot, SlotKind,
    TamperKind, UnlockedVault, Uuid, VaultError,
};

const T1: u64 = 1_700_000_000_000;

fn new_pw() -> SecretString {
    secret("the new password")
}

fn random_kek() -> SecretVec<u8> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SecretVec::new(bytes)
}

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// Two devices holding the same vault (3 items), both unlocked by password.
fn two_devices() -> (UnlockedVault, UnlockedVault) {
    let mut a = new_vault();
    populate(&mut a, 3);
    let b = unlock(&a.serialize()).unwrap();
    assert_vaults_eq(&a, &b);
    (a, b)
}

fn opens_with(bytes: &[u8], password: &SecretString) -> Result<UnlockedVault, VaultError> {
    LockedVault::parse(bytes)?.unlock(password)
}

fn slot_ids(v: &UnlockedVault) -> Vec<Uuid> {
    v.slots().map(|(id, _)| id).collect()
}

fn header_key(file: &VaultFile, key: &str) -> Option<Value> {
    let Value::Map(entries) = file.header.to_value() else {
        panic!("header is a map");
    };
    entries
        .into_iter()
        .find(|(k, _)| k == &t(key))
        .map(|(_, v)| v)
}

#[test]
fn fresh_vault_is_stamped_at_creation_and_every_slot_mutation_stamps_monotonically() {
    // 01 §2: `create` stamps `created_at` (seconds) as millis and records the device, so the
    // header is digest-bound from the first save. `create` (created_at 0) stamps 1, which
    // still reads as "newer than never stamped" (0) in the merge.
    let zero = UnlockedVault::create(&pw(), KdfParams::for_tests(), device());
    assert_eq!(zero.header().slots_modified_at, Some(1));
    assert_eq!(zero.header().slots_device_id, Some(device()));
    let mut v = new_vault(); // created_at 1_700_000_000 s
    assert_eq!(v.header().slots_modified_at, Some(T1));
    assert_eq!(v.header().slots_device_id, Some(device()));
    assert_eq!(v.header().slots_stamp(), T1);

    // Same clock as the creation stamp: still strictly advances.
    v.change_password(&pw(), &new_pw(), KdfParams::for_tests(), T1)
        .unwrap();
    assert_eq!(v.header().slots_modified_at, Some(T1 + 1));
    assert_eq!(v.header().slots_device_id, Some(device()));

    // A clock that went backwards still advances the stamp: max(now, prev + 1).
    let kek = random_kek();
    let id = v.add_enclave_slot(&kek, T1 - 500);
    assert_eq!(v.header().slots_modified_at, Some(T1 + 2));
    v.remove_slot(id, T1 + 10).unwrap();
    assert_eq!(v.header().slots_modified_at, Some(T1 + 10));
    v.rotate_vault_key(&new_pw(), 0).unwrap();
    assert_eq!(v.header().slots_modified_at, Some(T1 + 11));
    let id = v.add_enclave_slot_with_created_at(&kek, 1, T1 + 20);
    assert_eq!(v.header().slots_modified_at, Some(T1 + 20));

    // Failed mutations do not stamp.
    assert!(
        v.change_password(&pw(), &new_pw(), KdfParams::for_tests(), T1 + 100)
            .is_err()
    );
    assert!(v.remove_slot(Uuid::new_v4(), T1 + 100).is_err());
    assert!(v.rotate_vault_key(&pw(), T1 + 100).is_err());
    assert_eq!(v.header().slots_modified_at, Some(T1 + 20));

    // The stamp survives a save and is visible before unlock.
    let bytes = v.serialize();
    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(locked.header().slots_modified_at, Some(T1 + 20));
    assert_eq!(locked.header().slots_stamp(), T1 + 20);
    let reopened = locked.unlock(&new_pw()).unwrap();
    assert_eq!(reopened.header().slots_modified_at, Some(T1 + 20));
    assert_eq!(reopened.header().slots_device_id, Some(device()));
    assert!(slot_ids(&reopened).contains(&id));
}

#[test]
fn stamp_key_is_written_only_once_set() {
    // A v1.0 (never-stamped) file saved by this build stays key-free ...
    let mut v = unstamped_vault();
    populate(&mut v, 1);
    let file = VaultFile::parse(&v.serialize()).unwrap();
    assert_eq!(file.header.slots_modified_at, None);
    assert_eq!(
        header_key(&file, "slots_modified_at"),
        None,
        "never-stamped: no key"
    );
    assert_eq!(header_key(&file, "slots_device_id"), None);
    // ... while a freshly created vault writes both keys from its very first save.
    let fresh = VaultFile::parse(&new_vault().serialize()).unwrap();
    assert_eq!(
        header_key(&fresh, "slots_modified_at"),
        Some(Value::from(T1))
    );
    assert_eq!(
        header_key(&fresh, "slots_device_id"),
        Some(Value::Bytes(device().as_bytes().to_vec()))
    );

    v.change_password(&pw(), &new_pw(), KdfParams::for_tests(), T1)
        .unwrap();
    let bytes = v.serialize();
    let file = VaultFile::parse(&bytes).unwrap();
    assert_eq!(
        header_key(&file, "slots_modified_at"),
        Some(Value::from(T1))
    );
    assert_eq!(
        header_key(&file, "slots_device_id"),
        Some(Value::Bytes(device().as_bytes().to_vec()))
    );
    assert_eq!(file.to_bytes(), bytes, "canonical with the keys present");
}

#[test]
fn stamp_of_the_wrong_type_is_malformed_and_null_reads_as_missing() {
    let v = unstamped_vault();
    let key = t("slots_modified_at");
    // No stamp is set, so an extra with that name is emitted as-is by the writer.
    let bad = rewrite(&v.serialize(), |f| {
        f.header.extras.push((key.clone(), t("soon")));
    });
    assert!(matches!(
        LockedVault::parse(&bad),
        Err(VaultError::Malformed(m)) if m.contains("slots_modified_at")
    ));
    let null = rewrite(&v.serialize(), |f| {
        f.header.extras.push((key, Value::Null));
        f.header.extras.push((t("slots_device_id"), Value::Null));
    });
    let locked = LockedVault::parse(&null).unwrap();
    assert_eq!(locked.header().slots_modified_at, None);
    assert_eq!(locked.header().slots_device_id, None);
    assert!(locked.unlock(&pw()).is_ok());
    let bad_by = rewrite(&v.serialize(), |f| {
        f.header
            .extras
            .push((t("slots_device_id"), Value::Bytes(vec![1, 2, 3])));
    });
    assert!(matches!(
        LockedVault::parse(&bad_by),
        Err(VaultError::Malformed(m)) if m.contains("slots_device_id")
    ));
}

#[test]
fn password_change_and_recalibration_on_b_survive_a_merge() {
    let (mut a, mut b) = two_devices();
    let mut params = KdfParams::for_tests();
    params.m_cost_kib = 16 * 1024;
    params.t_cost = 2;
    b.change_password(&pw(), &new_pw(), params.clone(), T1)
        .unwrap();
    // A keeps editing with its (unchanged) key, as it would before the next sync.
    let id = a.items().next().unwrap().id;
    a.set_field_named(id, "password", secret("edited on A"), T1 + 1)
        .unwrap();

    let b_disk = opens_with(&b.serialize(), &new_pw()).unwrap();
    let report = a.merge_from(&b_disk).unwrap();
    assert!(report.header_updated, "{report:?}");
    assert!(report.changed());
    // Created at T1 (creation stamp), changed at T1 -> max(T1, T1 + 1).
    assert_eq!(a.header().slots_modified_at, Some(T1 + 1));
    assert_eq!(a.header().kdf, params);
    assert_eq!(a.header().slots, b.header().slots);

    let bytes = a.serialize();
    assert_eq!(
        opens_with(&bytes, &pw()).unwrap_err(),
        VaultError::WrongPassword,
        "the old password no longer opens A's save"
    );
    let reopened = opens_with(&bytes, &new_pw()).unwrap();
    assert_eq!(LockedVault::parse(&bytes).unwrap().kdf_params(), &params);
    assert_vaults_eq(&a, &reopened);
    assert_eq!(
        reopened
            .get(id)
            .unwrap()
            .field("password")
            .unwrap()
            .value
            .expose_secret(),
        "edited on A",
        "A's items are still there, under the unchanged vault key"
    );

    // Idempotent, and the other direction keeps B's (newer) header.
    let again = a.merge_from(&b_disk).unwrap();
    assert!(!again.changed(), "{again:?}");
    let before = b.header().clone();
    let r = b.merge_from(&a).unwrap();
    assert!(!r.header_updated);
    assert_eq!(b.header(), &before);
}

#[test]
fn enclave_slot_added_on_b_survives_a_merge() {
    let (mut a, mut b) = two_devices();
    let kek = random_kek();
    let slot = b.add_enclave_slot(&kek, T1);
    let b_disk = unlock(&b.serialize()).unwrap();

    let report = a.merge_from(&b_disk).unwrap();
    assert!(report.header_updated);
    assert_eq!(slot_ids(&a), slot_ids(&b));
    let locked = LockedVault::parse(&a.serialize()).unwrap();
    assert_vaults_eq(&a, &locked.unlock_with_kek(slot, &kek).unwrap());
    assert_vaults_eq(&a, &locked.unlock(&pw()).unwrap());

    // And a removal on B later wins over A's copy that still has the slot.
    b.remove_slot(slot, T1 + 5).unwrap();
    let report = a.merge_from(&b).unwrap();
    assert!(report.header_updated);
    assert_eq!(
        a.slots().map(|(_, k)| k).collect::<Vec<_>>(),
        [SlotKind::Password]
    );
    assert!(matches!(
        LockedVault::parse(&a.serialize())
            .unwrap()
            .unlock_with_kek(slot, &kek),
        Err(VaultError::Malformed(_))
    ));
}

#[test]
fn greater_stamp_wins_in_both_directions_and_tie_keeps_ours() {
    let (mut a, mut b) = two_devices();
    let pw_a = secret("A's password");
    let pw_b = secret("B's password");
    b.change_password(&pw(), &pw_b, KdfParams::for_tests(), T1)
        .unwrap();
    a.change_password(&pw(), &pw_a, KdfParams::for_tests(), T1 + 1_000)
        .unwrap();
    let a_snap = opens_with(&a.serialize(), &pw_a).unwrap();
    let b_snap = opens_with(&b.serialize(), &pw_b).unwrap();

    // A merges B: A's stamp is greater, keep A's.
    let r = a.merge_from(&b_snap).unwrap();
    assert!(!r.header_updated);
    assert!(!r.changed());
    let bytes = a.serialize();
    assert!(opens_with(&bytes, &pw_a).is_ok());
    assert_eq!(
        opens_with(&bytes, &pw_b).unwrap_err(),
        VaultError::WrongPassword
    );

    // B merges A: takes A's.
    let r = b.merge_from(&a_snap).unwrap();
    assert!(r.header_updated);
    assert_eq!(b.header().slots_modified_at, Some(T1 + 1_000));
    assert_eq!(b.header().slots, a.header().slots);
    assert_eq!(b.header().kdf, a.header().kdf);
    let bytes = b.serialize();
    assert!(opens_with(&bytes, &pw_a).is_ok());
    assert_eq!(
        opens_with(&bytes, &pw_b).unwrap_err(),
        VaultError::WrongPassword
    );

    // Exact tie on stamp *and* `slots_device_id` (e.g. the same change seen twice): keep
    // ours, so the merge stays idempotent. The device-id tie-break itself is covered by
    // `equal_stamps_are_broken_by_device_id_and_converge_both_ways`.
    let (mut a, mut b) = two_devices();
    b.set_device_id(a.device_id());
    a.change_password(&pw(), &pw_a, KdfParams::for_tests(), T1)
        .unwrap();
    b.change_password(&pw(), &pw_b, KdfParams::for_tests(), T1)
        .unwrap();
    assert_eq!(a.header().slots_device_id, b.header().slots_device_id);
    let (ha, hb) = (a.header().clone(), b.header().clone());
    assert!(!a.merge_from(&b).unwrap().header_updated);
    assert!(!b.merge_from(&a).unwrap().header_updated);
    assert_eq!(a.header(), &ha);
    assert_eq!(b.header(), &hb);

    // A side that has never stamped loses to any stamp, and never wins over one.
    let (mut a, mut b) = two_devices();
    b.change_password(&pw(), &pw_b, KdfParams::for_tests(), 1)
        .unwrap();
    assert!(a.merge_from(&b).unwrap().header_updated);
    assert!(!b.merge_from(&a).unwrap().header_updated);
}

/// 03 §5: equal `slots_modified_at` -> the greater `slots_device_id` bytes win, on both
/// sides, so the devices converge instead of each keeping its own header.
#[test]
fn equal_stamps_are_broken_by_device_id_and_converge_both_ways() {
    let dev_lo = Uuid::from_u128(0x1111_1111_1111_1111_1111_1111_1111_1111);
    let dev_hi = Uuid::from_u128(0xEEEE_EEEE_EEEE_EEEE_EEEE_EEEE_EEEE_EEEE);
    let pw_lo = secret("low device's password");
    let pw_hi = secret("high device's password");
    let (mut lo, mut hi) = two_devices();
    lo.set_device_id(dev_lo);
    hi.set_device_id(dev_hi);
    lo.change_password(&pw(), &pw_lo, KdfParams::for_tests(), T1)
        .unwrap();
    hi.change_password(&pw(), &pw_hi, KdfParams::for_tests(), T1)
        .unwrap();
    assert_eq!(lo.header().slots_stamp(), hi.header().slots_stamp());
    assert_eq!(lo.header().slots_device_id, Some(dev_lo));
    assert_eq!(hi.header().slots_device_id, Some(dev_hi));
    let hi_slots = hi.header().slots.clone();

    // As vault-sync does, the disk copy is opened with the *local* device id: the persisted
    // `slots_device_id`, not the in-memory one, must decide.
    let lo_disk = opens_with(&lo.serialize(), &pw_lo).unwrap();
    let hi_disk = opens_with(&hi.serialize(), &pw_hi).unwrap();
    assert_eq!(lo_disk.device_id(), hi_disk.device_id());

    let r = lo.merge_from(&hi_disk).unwrap();
    assert!(r.header_updated, "{r:?}");
    let r = hi.merge_from(&lo_disk).unwrap();
    assert!(!r.header_updated, "{r:?}");
    assert_eq!(lo.header().slots, hi_slots);
    assert_eq!(hi.header().slots, hi_slots);
    assert_eq!(
        lo.header(),
        hi.header(),
        "identical headers after one round"
    );
    for v in [&lo, &hi] {
        let bytes = v.serialize();
        assert!(opens_with(&bytes, &pw_hi).is_ok());
        assert_eq!(
            opens_with(&bytes, &pw_lo).unwrap_err(),
            VaultError::WrongPassword
        );
    }
    // Idempotent afterwards in both directions.
    assert!(!lo.merge_from(&hi_disk).unwrap().header_updated);
    assert!(!hi.merge_from(&lo_disk).unwrap().header_updated);
    assert!(!lo.merge_from(&lo_disk).unwrap().header_updated);

    // Two never-stamped headers tie and keep ours. A missing device id sorts below any
    // present one, even the nil UUID, at an equal stamp.
    let (mut a, b) = two_devices();
    assert!(!a.merge_from(&b).unwrap().header_updated);
    let (mut a, mut b) = two_devices();
    a.set_device_id(Uuid::nil());
    a.change_password(&pw(), &pw_lo, KdfParams::for_tests(), T1)
        .unwrap();
    b.set_device_id(Uuid::nil());
    b.change_password(&pw(), &pw_hi, KdfParams::for_tests(), T1)
        .unwrap();
    assert_eq!(a.header().slots_device_id, Some(Uuid::nil()));
    assert_eq!(b.header().slots_device_id, Some(Uuid::nil()));
    assert!(
        !a.merge_from(&b).unwrap().header_updated,
        "equal: keep ours"
    );
    // A stamped header *without* a device id is never written by this crate, and since the
    // id is digest-bound (01 §4) it cannot be produced by editing a file either; the
    // "missing sorts below any present" rule is `Option`'s ordering and is only reachable
    // through a future writer.
    let bytes = rewrite(&a.serialize(), |f| f.header.slots_device_id = None);
    assert_eq!(
        opens_with(&bytes, &pw_lo).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn opaque_slots_and_kdf_extras_travel_with_the_header() {
    // Both devices start from an unstamped (v1.0) file so the opaque slot and kdf extra can
    // be spliced in by hand; a fresh vault's header is digest-bound (01 §4).
    let mut a = unstamped_vault();
    populate(&mut a, 3);
    let b = unlock(&a.serialize()).unwrap();
    // B is a newer build: its file carries an opaque slot and an unknown key in `kdf`, and it
    // then adds an enclave slot (which stamps the header).
    let opaque = OpaqueSlot::new(
        Uuid::from_bytes([7; 16]),
        "future-kind",
        vec![(t("blob"), Value::Bytes(vec![1, 2, 3]))],
    )
    .unwrap();
    let kdf_extra = (t("x_kdf"), Value::Integer(1.into()));
    let bytes = rewrite(&b.serialize(), |f| {
        f.header.slots.insert(0, Slot::Opaque(opaque.clone()));
        f.header.kdf_extras.push(kdf_extra.clone());
    });
    let mut b = unlock(&bytes).unwrap();
    let kek = random_kek();
    let enclave = b.add_enclave_slot(&kek, T1);

    let report = a.merge_from(&b).unwrap();
    assert!(report.header_updated);
    assert_eq!(a.header().slots[0], Slot::Opaque(opaque.clone()));
    assert_eq!(a.header().kdf_extras, vec![kdf_extra.clone()]);
    assert_eq!(
        a.slots().map(|(_, k)| k).collect::<Vec<_>>(),
        [
            SlotKind::Other("future-kind".to_owned()),
            SlotKind::Password,
            SlotKind::Enclave
        ]
    );
    let locked = LockedVault::parse(&a.serialize()).unwrap();
    assert_eq!(locked.header().slots[0], Slot::Opaque(opaque));
    assert_eq!(locked.header().kdf_extras, vec![kdf_extra]);
    assert_vaults_eq(&a, &locked.unlock_with_kek(enclave, &kek).unwrap());
}

#[test]
fn key_rotation_on_b_is_adopted_together_with_its_key() {
    let (mut a, mut b) = two_devices();
    let id = a.items().next().unwrap().id;
    a.set_field_named(id, "password", secret("edited on A"), T1)
        .unwrap();
    b.rotate_vault_key(&pw(), T1 + 5).unwrap();
    let slots_b = b.header().slots.clone();

    // vault-sync: `unlock_with_key` with A's cached key fails on this file
    // (KeyRotatedOnDisk), the user re-enters the password, and the merge runs on the result.
    let b_disk = unlock(&b.serialize()).unwrap();
    let report = a.merge_from(&b_disk).unwrap();
    assert!(report.header_updated);
    assert_eq!(a.header().slots, slots_b);

    // A's save is self-consistent: slots and items agree on the (rotated) key, and A's edit
    // is in it.
    let merged = a.serialize();
    let reopened = unlock(&merged).unwrap();
    assert_vaults_eq(&a, &reopened);
    assert_eq!(
        reopened
            .get(id)
            .unwrap()
            .field("password")
            .unwrap()
            .value
            .expose_secret(),
        "edited on A"
    );
    // B opens A's save with its own (rotated) in-memory state too: same key.
    let r = b.merge_from(&reopened).unwrap();
    assert!(!r.header_updated);
    assert!(r.updated == 1, "{r:?}");
    assert_vaults_eq(&a, &b);
}

#[test]
fn later_local_password_change_beats_remote_rotation() {
    let (mut a, mut b) = two_devices();
    b.rotate_vault_key(&pw(), T1).unwrap();
    let pw_a = secret("A's later password");
    a.change_password(&pw(), &pw_a, KdfParams::for_tests(), T1 + 1)
        .unwrap();
    let slots_a = a.header().slots.clone();

    // A adopts nothing: its header (and therefore its original key) is newer.
    let b_disk = unlock(&b.serialize()).unwrap();
    let r = a.merge_from(&b_disk).unwrap();
    assert!(!r.header_updated);
    let bytes = a.serialize();
    assert_vaults_eq(&a, &opens_with(&bytes, &pw_a).unwrap());

    // B takes A's header AND A's key, so its save is openable with A's password and the
    // rotation is undone (LWW on the header).
    let a_disk = opens_with(&bytes, &pw_a).unwrap();
    let r = b.merge_from(&a_disk).unwrap();
    assert!(r.header_updated);
    assert_eq!(b.header().slots, slots_a);
    let bytes = b.serialize();
    assert_eq!(
        opens_with(&bytes, &pw()).unwrap_err(),
        VaultError::WrongPassword
    );
    assert_vaults_eq(&b, &opens_with(&bytes, &pw_a).unwrap());
}

/// 01 §4 `header_digest` (reviewer W1): once a header is stamped, its kdf + slots + stamp +
/// device id are bound into the manifest AAD, so a file-writing attacker cannot replay an
/// old header with a raised stamp, strip the stamp, or swap slots without the vault key.
#[test]
fn stamped_header_is_bound_into_the_manifest() {
    let mut v = unstamped_vault();
    populate(&mut v, 2);
    let old = v.serialize(); // unstamped (v1.0): old AAD, still opens with the old password
    v.change_password(&pw(), &new_pw(), KdfParams::for_tests(), T1)
        .unwrap();
    let cur = v.serialize(); // stamped at T1 by `device()`
    assert!(unlock(&old).is_ok());
    assert!(opens_with(&cur, &new_pw()).is_ok());
    let old_header = VaultFile::parse(&old).unwrap().header;
    let manifest = VaultError::Tampered(TamperKind::Manifest);

    // Captured old header (old password's slots) + raised stamp + current body: the old
    // password unwraps the replayed slot, then the manifest tag fails.
    let replayed = rewrite(&cur, |f| {
        let mut h = old_header.clone();
        h.slots_modified_at = Some(T1 + 1);
        h.slots_device_id = Some(device());
        f.header = h;
    });
    assert_eq!(opens_with(&replayed, &pw()).unwrap_err(), manifest);
    assert_eq!(
        opens_with(&replayed, &new_pw()).unwrap_err(),
        VaultError::WrongPassword,
        "the new password does not match the replayed slots at all"
    );
    // Old slots (with the KDF salt they were wrapped under) put back, stamp kept: the old
    // password unwraps them, then the manifest tag fails.
    let swapped = rewrite(&cur, |f| {
        f.header.slots = old_header.slots.clone();
        f.header.kdf = old_header.kdf.clone();
    });
    assert_eq!(opens_with(&swapped, &pw()).unwrap_err(), manifest);
    // Stamp stripped (with and without the device id).
    let stripped = rewrite(&cur, |f| {
        f.header.slots_modified_at = None;
        f.header.slots_device_id = None;
    });
    assert_eq!(opens_with(&stripped, &new_pw()).unwrap_err(), manifest);
    let no_id = rewrite(&cur, |f| f.header.slots_device_id = None);
    assert_eq!(opens_with(&no_id, &new_pw()).unwrap_err(), manifest);
    // Stamp raised, to the maximum, or lowered; device id changed.
    for edit in [
        (|h: &mut vault_core::Header| h.slots_modified_at = Some(T1 + 1))
            as fn(&mut vault_core::Header),
        |h| h.slots_modified_at = Some(u64::MAX),
        |h| h.slots_modified_at = Some(1),
        |h| h.slots_device_id = Some(Uuid::from_u128(u128::MAX)),
        |h| h.kdf_extras.push((t("x"), Value::Null)),
    ] {
        let tampered = rewrite(&cur, |f| edit(&mut f.header));
        assert_eq!(opens_with(&tampered, &new_pw()).unwrap_err(), manifest);
    }
    // The KDF params are bound too, but a password unlock derives the wrong KEK first.
    let kdf = rewrite(&cur, |f| f.header.kdf.t_cost = 2);
    assert_eq!(
        opens_with(&kdf, &new_pw()).unwrap_err(),
        VaultError::WrongPassword
    );
    // An unstamped file is not affected by a stamp-free header edit of the same kind: the
    // old AAD has no digest, so e.g. adding a kdf extra still opens (01 §9 tolerance).
    let old_extra = rewrite(&old, |f| f.header.kdf_extras.push((t("x"), Value::Null)));
    assert!(unlock(&old_extra).is_ok());
    // And a stamp *added* to an unstamped file is caught: the writer's AAD had no digest.
    let added = rewrite(&old, |f| f.header.slots_modified_at = Some(T1));
    assert_eq!(unlock(&added).unwrap_err(), manifest);
}

#[test]
fn vault_id_mismatch_is_still_rejected_before_any_header_change() {
    let (mut a, _) = two_devices();
    let mut other = new_vault();
    other
        .change_password(&pw(), &new_pw(), KdfParams::for_tests(), T1)
        .unwrap();
    let before = a.header().clone();
    assert!(matches!(
        a.merge_from(&other),
        Err(VaultError::Malformed(_))
    ));
    assert_eq!(a.header(), &before);
}

/// Why `create` stamps (01 §2): on an *unstamped* header a by-hand edit of a key slot is not
/// bound into anything a key-holding device checks, so a device with the cached vault key
/// keeps opening the file, never rewrites the slot, and only the next password unlock fails.
/// A fresh vault is stamped from its first save, so the slot set is digest-bound into the
/// manifest AAD (01 §4) and the edit fails at open on every path.
#[test]
fn fresh_vault_slot_tamper_is_caught_at_open() {
    let manifest = VaultError::Tampered(TamperKind::Manifest);
    let mut v = new_vault();
    populate(&mut v, 2);
    let bytes = v.serialize();
    let header = LockedVault::parse(&bytes).unwrap().header().clone();
    assert_eq!(header.slots_modified_at, Some(T1));
    assert_eq!(header.slots_device_id, Some(device()));
    assert!(header.digest().is_some(), "fresh vault is digest-bound");

    // Password slot nonce flipped: the password path trips over the slot first (01 §7 says a
    // slot tag failure on a cleanly parsed header is `WrongPassword`), so it is reported as
    // such; the key-holding paths reach the manifest and report the tamper (sync_feature.rs
    // covers `unlock_with_key`).
    let nonce = rewrite(&bytes, |f| {
        f.header.slots[0].as_key_mut().unwrap().nonce[0] ^= 1
    });
    assert_eq!(unlock(&nonce).unwrap_err(), VaultError::WrongPassword);
    // A slot edit outside the slot AAD (`created_at`) still unwraps, then fails the manifest.
    let created = rewrite(&bytes, |f| {
        f.header.slots[0].as_key_mut().unwrap().created_at += 1
    });
    assert_eq!(unlock(&created).unwrap_err(), manifest);

    // With a second slot, flipping the *other* slot's nonce is caught by the password path
    // and by the enclave path alike.
    let kek = random_kek();
    let enclave = v.add_enclave_slot(&kek, T1 + 5);
    let bytes = v.serialize();
    let flip = |kind: SlotKind| {
        rewrite(&bytes, |f| {
            let slot = f
                .header
                .slots
                .iter_mut()
                .find(|s| s.is_key_of(kind.clone()));
            slot.unwrap().as_key_mut().unwrap().nonce[0] ^= 1;
        })
    };
    let enclave_flipped = flip(SlotKind::Enclave);
    assert_eq!(unlock(&enclave_flipped).unwrap_err(), manifest);
    let password_flipped = flip(SlotKind::Password);
    assert_eq!(
        LockedVault::parse(&password_flipped)
            .unwrap()
            .unlock_with_kek(enclave, &kek)
            .unwrap_err(),
        manifest
    );
}

/// Splicing the OLD unstamped header bytes verbatim over a stamped file (keeping the new
/// body) must fail the manifest check on both the password and the key-holding paths.
#[test]
fn old_unstamped_header_spliced_over_stamped_file_is_tampered() {
    let manifest = VaultError::Tampered(TamperKind::Manifest);
    let mut v = unstamped_vault();
    populate(&mut v, 2);
    let old = v.serialize();
    v.change_password(&pw(), &new_pw(), KdfParams::for_tests(), T1)
        .unwrap();
    #[cfg(feature = "sync")]
    let handle = v.export_vault_key();
    let cur = v.serialize();

    let old_file = VaultFile::parse(&old).unwrap();
    let old_header = old_file.header.clone();
    let old_bytes = old_header.to_bytes();
    let spliced = rewrite(&cur, |f| f.header = old_header);
    let contains = |hay: &[u8]| hay.windows(old_bytes.len()).any(|w| w == old_bytes);
    assert!(
        contains(&old) && contains(&spliced),
        "old header kept verbatim"
    );
    assert!(
        !contains(&cur),
        "the stamped header differs from the old one"
    );
    assert_eq!(opens_with(&spliced, &pw()).unwrap_err(), manifest);
    #[cfg(feature = "sync")]
    assert_eq!(
        LockedVault::parse(&spliced)
            .unwrap()
            .unlock_with_key(&handle, device())
            .unwrap_err(),
        manifest
    );
}
