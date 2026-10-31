//! Fixes for the independent bug hunt of 2026-10-31 (`docs/qa/bug-hunt-2026-10-31.md`):
//! H1 (the header merge must adopt the format version with the slots and never lower it),
//! M1 (a same-stamp field edit must converge: symmetric tie-break by canonical bytes), and
//! L1 (the field-marker cap must not resurrect removed fields on merge).

mod common;

use common::*;
use vault_core::format::VaultFile;
use vault_core::vault::FIELD_TOMBSTONE_CAP;
use vault_core::vault::merge::merge_items;
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, LockedVault, SecretVec, SlotKind, TamperKind,
    UnlockedVault, Uuid, VaultError,
};

fn dev_a() -> Uuid {
    Uuid::from_u128(0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA)
}

fn dev_b() -> Uuid {
    Uuid::from_u128(0xBBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB)
}

/// A version 1 vault (the unstamped fixture) with one item, and a second handle on the same
/// bytes. Both at version 1.
fn two_v1_handles() -> (UnlockedVault, UnlockedVault, Uuid) {
    let mut a = unstamped_vault();
    a.set_device_id(dev_a());
    let id = a.insert(sample_item(0, 1_000), 1_000);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    assert_eq!(a.header().format_version, 1);
    assert_eq!(b.header().format_version, 1);
    (a, b, id)
}

fn opens(bytes: &[u8]) -> UnlockedVault {
    LockedVault::parse(bytes)
        .unwrap()
        .unlock(&pw())
        .expect("the password opens the merged file")
}

fn kinds(v: &UnlockedVault) -> Vec<SlotKind> {
    v.slots().map(|(_, k)| k).collect()
}

// -------------------------------------------------------------------------------------------
// H1: version adoption
// -------------------------------------------------------------------------------------------

#[test]
fn v1_holder_merging_an_upgraded_copy_adopts_version_2_and_the_file_opens() {
    let (mut a, mut b, id) = two_v1_handles();
    // A (still version 1) enrols Touch ID with a NEWER stamp than B's upgrade; the upgrade
    // must still win because the version leads the header order.
    let kek = SecretVec::new(vec![0x42; 32]);
    let enclave = a.add_enclave_slot(&kek, 5_000);
    b.upgrade_format(&pw(), 3_000).unwrap();
    assert_eq!(b.header().format_version, 2);
    assert!(a.header().slots_stamp() > b.header().slots_stamp());
    // Some item traffic on both sides so the merge is not header-only.
    a.set_field_named(id, "username", secret("from-a"), 6_000)
        .unwrap();
    b.set_field_named(id, "password", secret("from-b"), 6_001)
        .unwrap();

    let b_snap = unlock(&b.serialize()).unwrap();
    let report = a.merge_from(&b_snap).unwrap();
    assert!(report.header_updated, "the upgraded header was adopted");
    assert_eq!(report.updated, 1);
    assert_eq!(
        a.header().format_version,
        2,
        "version travels with the slots"
    );
    assert_eq!(a.header().slots_modified_at, b.header().slots_modified_at);
    assert_eq!(
        kinds(&a),
        [SlotKind::Password],
        "the version 1 enclave enrolment is dropped with the version 1 slot set"
    );

    let bytes = a.serialize();
    assert_eq!(&bytes[4..6], &[0, 2], "written at version 2");
    let reopened = opens(&bytes);
    assert_eq!(reopened.header().format_version, 2);
    assert_eq!(
        reopened
            .get(id)
            .unwrap()
            .field("password")
            .unwrap()
            .value
            .expose_secret(),
        "from-b"
    );
    assert_eq!(
        reopened
            .get(id)
            .unwrap()
            .field("username")
            .unwrap()
            .value
            .expose_secret(),
        "from-a"
    );
    assert!(matches!(
        LockedVault::parse(&bytes)
            .unwrap()
            .unlock_with_kek(enclave, &kek)
            .unwrap_err(),
        VaultError::Malformed(_)
    ));
    // The header digest binding still holds on the adopted header: stripping or
    // re-stamping it fails the manifest on the password path.
    let stripped = rewrite(&bytes, |f| {
        f.header.slots_modified_at = None;
        f.header.slots_device_id = None;
    });
    assert_eq!(
        unlock(&stripped).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    let raised = rewrite(&bytes, |f| {
        f.header.slots_modified_at = Some(f.header.slots_modified_at.unwrap() + 1)
    });
    assert_eq!(
        unlock(&raised).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    // A prefix edited back to version 1 fails every slot (the AAD binds the version).
    let mut downgraded = bytes.clone();
    downgraded[5] = 1;
    assert_eq!(unlock(&downgraded).unwrap_err(), VaultError::WrongPassword);
}

#[test]
fn v2_holder_merging_a_newer_v1_header_keeps_version_2_and_its_slots() {
    let (mut a, mut b, id) = two_v1_handles();
    a.upgrade_format(&pw(), 3_000).unwrap();
    let v2_slots = a.header().slots.clone();
    // B, still on the old version, changes the password and enrols Touch ID later.
    let new_pw = secret("changed on the old build");
    b.change_password(&pw(), &new_pw, vault_core::KdfParams::for_tests(), 4_000)
        .unwrap();
    let kek = SecretVec::new(vec![0x24; 32]);
    b.add_enclave_slot(&kek, 5_000);
    b.set_field_named(id, "username", secret("from-b"), 5_001)
        .unwrap();
    assert!(b.header().slots_stamp() > a.header().slots_stamp());

    let b_snap = LockedVault::parse(&b.serialize())
        .unwrap()
        .unlock(&new_pw)
        .unwrap();
    let report = a.merge_from(&b_snap).unwrap();
    assert!(
        !report.header_updated,
        "a newer version 1 header never wins"
    );
    assert_eq!(report.updated, 1, "items still merge");
    assert_eq!(a.header().format_version, 2);
    assert_eq!(a.header().slots, v2_slots, "version 2 slots untouched");
    assert_eq!(a.header().slots_modified_at, Some(3_000));
    let bytes = a.serialize();
    assert_eq!(&bytes[4..6], &[0, 2]);
    let reopened = opens(&bytes);
    assert_eq!(
        reopened
            .get(id)
            .unwrap()
            .field("username")
            .unwrap()
            .value
            .expose_secret(),
        "from-b"
    );
    // The old-build password change and enrolment are dropped: the OLD password opens
    // the merged file, the new one and the enclave KEK do not. Documented consequence.
    assert_eq!(
        LockedVault::parse(&bytes)
            .unwrap()
            .unlock(&new_pw)
            .unwrap_err(),
        VaultError::WrongPassword
    );
    assert_eq!(kinds(&reopened), [SlotKind::Password]);

    // The other direction: B (version 1, newer stamp) merging A adopts version 2 and A's
    // slots, so both converge on the same header.
    let a_snap = unlock(&bytes).unwrap();
    let report = b.merge_from(&a_snap).unwrap();
    assert!(report.header_updated);
    assert_eq!(b.header().format_version, 2);
    assert_eq!(b.header().slots, v2_slots);
    assert!(opens(&b.serialize()).header().format_version == 2);
    assert_eq!(b.header(), a.header());
}

#[test]
fn version_adoption_is_idempotent_and_commutative_and_never_lowers() {
    let (mut a, mut b, id) = two_v1_handles();
    b.upgrade_format(&pw(), 3_000).unwrap();
    a.set_field_named(id, "username", secret("a"), 4_000)
        .unwrap();
    b.set_field_named(id, "notes", secret("b"), 4_000).unwrap();
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();

    // Order 1: A takes B.  Order 2: B takes A.
    let mut a1 = unlock(&a.serialize()).unwrap();
    a1.set_device_id(dev_a());
    a1.merge_from(&b_snap).unwrap();
    let mut b1 = unlock(&b.serialize()).unwrap();
    b1.set_device_id(dev_b());
    let r = b1.merge_from(&a_snap).unwrap();
    assert!(
        !r.header_updated,
        "version 2 never takes a version 1 header"
    );
    assert_eq!(
        a1.header(),
        b1.header(),
        "both orders end on the same header"
    );
    assert_eq!(a1.header().format_version, 2);
    assert!(
        !a1.merge_from(&b_snap).unwrap().header_updated,
        "idempotent"
    );
    assert!(!b1.merge_from(&a_snap).unwrap().changed(), "idempotent");
    // Second round over serialized copies converges items too.
    let a1_snap = unlock(&a1.serialize()).unwrap();
    let b1_snap = unlock(&b1.serialize()).unwrap();
    a1.merge_from(&b1_snap).unwrap();
    b1.merge_from(&a1_snap).unwrap();
    assert_vaults_eq(&a1, &b1);
    opens(&a1.serialize());
    opens(&b1.serialize());

    // A merge of two equal-version headers behaves as before (stamp, then device id).
    let (mut c, mut d, _) = two_v1_handles();
    c.change_password(&pw(), &pw(), vault_core::KdfParams::for_tests(), 2_000)
        .unwrap();
    assert!(d.merge_from(&c).unwrap().header_updated);
    assert_eq!(
        d.header().format_version,
        1,
        "stays version 1: nothing to raise"
    );
    assert!(!c.merge_from(&d).unwrap().header_updated);
}

/// The hunt's two conflict-copy shapes are, at the core level, "a stale handle merges the
/// on-disk copy before writing": a version 1 handle that was open before another device
/// upgraded the file must produce an openable file from both the in-package and the
/// sibling copy, which differ only in where vault-sync found the bytes.
#[test]
fn stale_v1_handle_merging_an_upgraded_disk_copy_writes_an_openable_file() {
    let (mut stale, mut other, id) = two_v1_handles();
    other.upgrade_format(&pw(), 3_000).unwrap();
    other
        .set_field_named(id, "password", secret("after-upgrade"), 3_500)
        .unwrap();
    let disk = other.serialize();
    for shape in ["in-package vault 2.bin", "sibling cc 2.vault"] {
        let mut handle = unlock(&stale.serialize()).unwrap();
        handle.set_device_id(dev_a());
        handle
            .set_field_named(id, "username", secret("unsaved edit"), 3_600)
            .unwrap();
        let copy = unlock(&disk).unwrap();
        let report = handle.merge_from(&copy).unwrap();
        assert!(report.header_updated, "{shape}");
        let bytes = handle.serialize();
        let v = opens(&bytes);
        assert_eq!(v.header().format_version, 2, "{shape}");
        assert_eq!(
            v.get(id)
                .unwrap()
                .field("password")
                .unwrap()
                .value
                .expose_secret(),
            "after-upgrade",
            "{shape}"
        );
        assert_eq!(
            v.get(id)
                .unwrap()
                .field("username")
                .unwrap()
                .value
                .expose_secret(),
            "unsaved edit",
            "{shape}"
        );
        assert_eq!(VaultFile::parse(&bytes).unwrap().header.format_version, 2);
    }
    // And the stale handle itself, never merged, still writes a valid version 1 file.
    stale.set_field_named(id, "url", secret("x"), 1).unwrap();
    let v1 = stale.serialize();
    assert_eq!(&v1[4..6], &[0, 1]);
    opens(&v1);
}

// -------------------------------------------------------------------------------------------
// M1: symmetric tie-break
// -------------------------------------------------------------------------------------------

/// Two devices with the same vault; A's device id bytes are smaller than B's.
fn two_devices() -> (UnlockedVault, UnlockedVault, Uuid) {
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(sample_item(0, 1_000), 1_000);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    (a, b, id)
}

#[test]
fn same_stamp_field_edits_converge_in_one_round_both_ways() {
    // The hunt's mi10: A and B edit the same field with the same stamp; B also edits the
    // title later, so after one merge both items carry B's device id and the old tie-break
    // fell to "ours" on each side forever.
    let (mut a, mut b, id) = two_devices();
    let username = a.get(id).unwrap().field("username").unwrap().id;
    a.set_field(id, username, secret("from-A"), 5_000).unwrap();
    b.set_field(id, username, secret("from-B"), 5_000).unwrap();
    b.update(id, 6_000, |i| i.title = "B title".into()).unwrap();

    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    let va = a
        .get(id)
        .unwrap()
        .field_by_id(username)
        .unwrap()
        .value
        .expose_secret()
        .clone();
    let vb = b
        .get(id)
        .unwrap()
        .field_by_id(username)
        .unwrap()
        .value
        .expose_secret()
        .clone();
    assert_eq!(va, vb, "one round: both sides hold the same value");
    assert!(va == "from-A" || va == "from-B");
    assert_eq!(a.get(id).unwrap().title, "B title");
    assert_eq!(b.get(id).unwrap().title, "B title");
    // Further rounds change nothing but the +1 stamp catch-up.
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert_vaults_eq(&a, &b);
    assert!(!a.merge_from(&b_snap).unwrap().changed());
    assert!(!b.merge_from(&a_snap).unwrap().changed());

    // Pure function check: with equal stamps and equal device ids the pick is symmetric
    // and depends only on the field bytes.
    let mut x = sample_item(1, 10);
    x.device_id = dev_a();
    let mut y = x.clone();
    x.fields[0].value = secret("aaa");
    y.fields[0].value = secret("zzz");
    let xy = merge_items(&x, &y);
    let yx = merge_items(&y, &x);
    assert_eq!(
        xy.fields[0].value.expose_secret(),
        yx.fields[0].value.expose_secret()
    );
    assert_eq!(
        xy.fields[0].value.expose_secret(),
        "zzz",
        "greater bytes win"
    );
}

#[test]
fn same_stamp_same_device_metadata_and_tombstones_pick_the_same_side() {
    // Both tombstones, equal (modified_at, device_id), different titles: both orders agree.
    let mut x = sample_item(2, 10);
    x.device_id = dev_a();
    let mut y = x.clone();
    x.title = "alpha".into();
    y.title = "omega".into();
    x.deleted_at = Some(10);
    y.deleted_at = Some(10);
    assert_eq!(merge_items(&x, &y).title, merge_items(&y, &x).title);
    // Both live, equal stamps and device id, different metadata and field order.
    x.deleted_at = None;
    y.deleted_at = None;
    y.fields.reverse();
    y.favorite = !x.favorite;
    let xy = merge_items(&x, &y);
    let yx = merge_items(&y, &x);
    assert_eq!(xy.title, yx.title);
    assert_eq!(xy.favorite, yx.favorite);
    assert_eq!(
        xy.fields.iter().map(|f| f.id).collect::<Vec<_>>(),
        yx.fields.iter().map(|f| f.id).collect::<Vec<_>>(),
        "field order agrees too"
    );
    // Through the vault: two devices whose items already share a device id (after an
    // earlier merge) make a same-stamp metadata edit; one round converges.
    let (mut a, mut b, id) = two_devices();
    b.update(id, 2_000, |i| i.tags.push("b".into())).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    assert_eq!(a.get(id).unwrap().device_id, dev_b());
    a.update(id, 3_000, |i| i.title = "A says".into()).unwrap();
    b.update(id, 3_000, |i| i.title = "B says".into()).unwrap();
    // Same stamp; A's item was stamped by A, B's by B, so device ids differ here and B
    // wins; force the hunt's shape by giving both the same device id.
    a.set_device_id(dev_b());
    a.update(id, 3_000, |i| i.title = "A says".into()).unwrap();
    b.update(id, 3_000, |i| i.title = "B says".into()).unwrap();
    assert_eq!(
        a.get(id).unwrap().modified_at,
        b.get(id).unwrap().modified_at
    );
    assert_eq!(a.get(id).unwrap().device_id, b.get(id).unwrap().device_id);
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert_eq!(a.get(id).unwrap().title, b.get(id).unwrap().title);
}

// -------------------------------------------------------------------------------------------
// L1: marker cap on merge
// -------------------------------------------------------------------------------------------

fn many_fields(n: usize) -> (Item, Vec<Uuid>) {
    let mut item = Item::new("Many", device(), 10);
    for i in 0..n {
        item.fields.push(Field::new(
            format!("f{i}"),
            FieldKind::Text,
            secret("x"),
            10,
        ));
    }
    let ids = item.fields.iter().map(|f| f.id).collect();
    (item, ids)
}

#[test]
fn seventy_removals_on_one_device_survive_the_merge_with_an_offline_peer() {
    let (item, ids) = many_fields(FIELD_TOMBSTONE_CAP + 6);
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(item, 10);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    for (i, f) in ids.iter().enumerate() {
        a.remove_field(id, *f, 100 + i as u64).unwrap();
    }
    assert_eq!(a.get(id).unwrap().removed_fields.len(), 70);

    // B (offline, untouched) merges A: nothing comes back, every marker kept because B
    // still carried the fields at merge time.
    let a_snap = unlock(&a.serialize()).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert!(b.get(id).unwrap().fields.is_empty(), "no resurrection");
    assert_eq!(
        b.get(id).unwrap().removed_fields.len(),
        70,
        "over the cap, on purpose"
    );
    // A merges B's new state: both sides now lack every field, so the cap applies.
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    assert!(a.get(id).unwrap().fields.is_empty());
    assert_eq!(a.get(id).unwrap().removed_fields.len(), FIELD_TOMBSTONE_CAP);
    assert_eq!(
        a.get(id).unwrap().removed_fields.last().unwrap().removed_at,
        106,
        "the oldest six went"
    );
    let a_snap = unlock(&a.serialize()).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert_vaults_eq(&a, &b);
    assert!(
        !a.merge_from(&unlock(&b.serialize()).unwrap())
            .unwrap()
            .changed()
    );

    // Two-sided: 40 removals per device of disjoint fields, both offline.
    let (item, ids) = many_fields(80);
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(item, 10);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    for (i, f) in ids[..40].iter().enumerate() {
        a.remove_field(id, *f, 100 + i as u64).unwrap();
    }
    for (i, f) in ids[40..].iter().enumerate() {
        b.remove_field(id, *f, 200 + i as u64).unwrap();
    }
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    for v in [&a, &b] {
        assert!(v.get(id).unwrap().fields.is_empty(), "nothing comes back");
        assert_eq!(v.get(id).unwrap().removed_fields.len(), 80);
    }
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    for v in [&a, &b] {
        assert!(v.get(id).unwrap().fields.is_empty());
        assert_eq!(v.get(id).unwrap().removed_fields.len(), FIELD_TOMBSTONE_CAP);
    }
    // One more round carries the `+1` stamp bump of the cap round across (merge docs).
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert_vaults_eq(&a, &b);
    assert!(!a.merge_from(&b_snap).unwrap().changed());
}
