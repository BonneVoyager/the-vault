//! Guarantees 4-7 and header tampering.

mod common;

use common::*;
use vault_core::format::VaultFile;
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, LockedVault, TamperKind, UnlockedVault, Uuid, VaultError,
};

#[test]
fn guarantee_4_flip_byte_in_item_ct() {
    let mut v = new_vault();
    populate(&mut v, 3);
    let bytes = v.serialize();
    let file = VaultFile::parse(&bytes).unwrap();
    for (idx, rec) in file.items.iter().enumerate() {
        let len = rec.ct.len();
        // first byte, middle, last plaintext byte, and inside the tag
        for pos in [0, len / 2, len - 17, len - 1] {
            let tampered = rewrite(&bytes, |f| f.items[idx].ct[pos] ^= 0x01);
            assert_eq!(
                unlock(&tampered).unwrap_err(),
                VaultError::Tampered(TamperKind::Item(rec.id)),
                "item {idx} byte {pos}"
            );
        }
    }
}

#[test]
fn flip_nonce_or_modified_at_is_item_tamper() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let bytes = v.serialize();
    let id = VaultFile::parse(&bytes).unwrap().items[1].id;
    let t = rewrite(&bytes, |f| f.items[1].nonce[3] ^= 0x80);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(id))
    );
    let t = rewrite(&bytes, |f| f.items[1].modified_at += 1);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(id))
    );
}

#[test]
fn guarantee_5_remove_item_record() {
    let mut v = new_vault();
    populate(&mut v, 4);
    let bytes = v.serialize();
    for idx in 0..4 {
        let t = rewrite(&bytes, |f| {
            f.items.remove(idx);
        });
        assert_eq!(
            unlock(&t).unwrap_err(),
            VaultError::Tampered(TamperKind::Manifest)
        );
    }
    let t = rewrite(&bytes, |f| {
        let dup = f.items[0].clone();
        f.items.push(dup);
    });
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    // duplicate while dropping another keeps the count equal; still caught by pair comparison
    let t = rewrite(&bytes, |f| {
        f.items[1] = f.items[0].clone();
    });
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn guarantee_6_rollback_item_record() {
    let mut v = new_vault();
    populate(&mut v, 3);
    let old = v.serialize();
    let id = VaultFile::parse(&old).unwrap().items[1].id;

    let mut item = v.get(id).unwrap().clone();
    item.title = "renamed".into();
    item.modified_at += 5;
    v.insert(item, 0);
    let new = v.serialize();

    let old_file = VaultFile::parse(&old).unwrap();
    let old_rec = old_file.items.iter().find(|r| r.id == id).unwrap().clone();
    let t = rewrite(&new, |f| {
        let slot = f.items.iter_mut().find(|r| r.id == id).unwrap();
        *slot = old_rec;
    });
    // The old record is genuine (its own AAD still verifies) so it decrypts; the manifest
    // cross-check is what catches the rollback.
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn flip_manifest_ct() {
    let mut v = new_vault();
    populate(&mut v, 2);
    let bytes = v.serialize();
    let t = rewrite(&bytes, |f| f.manifest.ct[0] ^= 1);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    let t = rewrite(&bytes, |f| f.manifest.nonce[0] ^= 1);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn guarantee_7_item_moved_between_vaults() {
    let mut a = new_vault();
    populate(&mut a, 2);
    let mut b = new_vault();
    populate(&mut b, 2);
    let ab = a.serialize();
    let bb = b.serialize();
    let foreign = VaultFile::parse(&ab).unwrap().items[0].clone();
    let foreign_id = foreign.id;

    // Append the foreign record.
    let t = rewrite(&bb, |f| f.items.push(foreign.clone()));
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(foreign_id)),
        "item AAD binds vault_id; checked before the manifest"
    );
    // Replace one of B's records with it (count unchanged).
    let t = rewrite(&bb, |f| f.items[1] = foreign.clone());
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Item(foreign_id))
    );
}

fn slot0(f: &mut vault_core::format::VaultFile) -> &mut vault_core::KeySlot {
    f.header.slots[0].as_key_mut().unwrap()
}

#[test]
fn header_tamper_reports_wrong_password() {
    let mut v = new_vault();
    populate(&mut v, 1);
    let bytes = v.serialize();

    let t = rewrite(&bytes, |f| {
        let mut b = *f.header.vault_id.as_bytes();
        b[0] ^= 1;
        f.header.vault_id = vault_core::Uuid::from_bytes(b);
    });
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| f.header.kdf.salt[0] ^= 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| f.header.kdf.t_cost += 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| slot0(f).wrapped_key[40] ^= 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| slot0(f).nonce[0] ^= 1);
    assert_eq!(unlock(&t).unwrap_err(), VaultError::WrongPassword);

    let t = rewrite(&bytes, |f| {
        slot0(f).id = vault_core::Uuid::from_u128(9);
    });
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::WrongPassword,
        "slot id is in the AAD"
    );

    // Relabelling the only password slot leaves no password slot at all: that is reported as
    // `NoUsableSlot` (not `WrongPassword`) so the app can explain it; see forward_compat.rs.
    let t = rewrite(&bytes, |f| slot0(f).kind = vault_core::SlotKind::Enclave);
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::NoUsableSlot,
        "no password slot left"
    );

    // Invalid Argon2 params are structural damage, not a wrong password.
    let t = rewrite(&bytes, |f| f.header.kdf.m_cost_kib = 1);
    assert!(matches!(unlock(&t).unwrap_err(), VaultError::Malformed(_)));
    assert!(
        LockedVault::parse(&t).is_ok(),
        "parse itself does not run the KDF"
    );
}

// ---------------------------------------------------------------------------------------
// Guarantee 6 after a merge (security review 2026-11-26 M-01)
// ---------------------------------------------------------------------------------------

/// Device O and device T, both open on the same file written by O, holding one item with a
/// username and a password. Returns `(o, t, id, username field id, password field id)`.
fn two_devices_one_login() -> (UnlockedVault, UnlockedVault, Uuid, Uuid, Uuid) {
    let (dev_o, dev_t) = (Uuid::from_u128(0x0A), Uuid::from_u128(0x0B));
    let mut o = new_vault();
    o.set_device_id(dev_o);
    let mut item = Item::new("Bank", dev_o, 1);
    item.fields
        .push(Field::new("username", FieldKind::Text, secret("alice"), 1));
    item.fields.push(Field::new(
        "password",
        FieldKind::Password,
        secret("old-password"),
        1,
    ));
    let id = o.insert(item, 1);
    let user_field = o.get(id).unwrap().field("username").unwrap().id;
    let pw_field = o.get(id).unwrap().field("password").unwrap().id;
    let mut t = unlock(&o.serialize()).unwrap();
    t.set_device_id(dev_t);
    (o, t, id, user_field, pw_field)
}

/// Appendix A of the review. O changes the password at 8; T edits the username at 10 and
/// its file is visible in the sync folder. O merges T's file: the result keeps T's
/// `modified_at` (10) with content T never wrote (O's new password). Before the symmetric
/// restamp, T's earlier record (same id, same stamp, same key and AAD) spliced over O's
/// saved record passed the manifest check and silently reverted the password.
#[test]
fn guarantee_6_holds_after_a_merge_that_keeps_the_peer_stamp() {
    let (mut o, mut t, id, user_field, pw_field) = two_devices_one_login();
    o.set_field(id, pw_field, secret("NEW-password"), 8)
        .unwrap();
    let pre_merge_o = o.serialize();
    t.set_field(id, user_field, secret("alice@example.com"), 10)
        .unwrap();
    let file_t = t.serialize();

    let on_disk_t = unlock(&file_t).unwrap();
    let report = o.merge_from(&on_disk_t).unwrap();
    assert_eq!(report.updated, 1);
    let merged = o.get(id).unwrap();
    assert_eq!(
        merged.field("username").unwrap().value.expose_secret(),
        "alice@example.com"
    );
    assert_eq!(
        merged.field("password").unwrap().value.expose_secret(),
        "NEW-password"
    );
    assert_eq!(
        merged.modified_at, 11,
        "a record neither side wrote is stamped past both inputs"
    );
    let file_o = o.serialize();

    // Attacker, no key: replace the item record in O's file with T's earlier record.
    let spliced = splice(&file_o, &file_t, id);
    assert_eq!(
        unlock(&spliced).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    // And with O's own pre-merge record.
    assert_eq!(
        unlock(&splice(&file_o, &pre_merge_o, id)).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    // The merged file itself is intact.
    assert_eq!(
        unlock(&file_o)
            .unwrap()
            .get(id)
            .unwrap()
            .field("password")
            .unwrap()
            .value
            .expose_secret(),
        "NEW-password"
    );
}

/// The tombstone variant named by the review: T deletes at 5 and strips at 20 (the stripped
/// tombstone is restamped to 20, `deleted_at` stays 5); O edits the password at 10. O merges
/// T: the edit is later than the delete, so the live item wins, at `max(10, 20)`. Before the
/// fix the merged live record carried T's stamp 20 and T's tombstone record could be
/// spliced over it, deleting the item.
#[test]
fn guarantee_6_holds_when_a_live_item_resurrects_over_a_stripped_tombstone() {
    let (mut o, mut t, id, _user_field, pw_field) = two_devices_one_login();
    o.set_field(id, pw_field, secret("NEW-password"), 10)
        .unwrap();
    t.delete(id, 5).unwrap();
    t.delete_permanently(id, 20).unwrap();
    let file_t = t.serialize();
    assert_eq!(unlock(&file_t).unwrap().get(id).unwrap().modified_at, 20);

    o.merge_from(&unlock(&file_t).unwrap()).unwrap();
    let merged = o.get(id).unwrap();
    assert!(!merged.is_deleted(), "the later edit resurrects");
    assert_eq!(merged.modified_at, 21);
    let file_o = o.serialize();

    assert_eq!(
        unlock(&splice(&file_o, &file_t, id)).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    assert!(!unlock(&file_o).unwrap().get(id).unwrap().is_deleted());
}

/// The `created_at`-only variant named by the review. T's copy has the same content as O's
/// with an earlier `created_at` (as if learnt from a third device) at the base stamp 1; O's
/// copy was restamped to 8 by a content-free `update`. O merges T and adopts the minimum:
/// the merged record (O's content and stamp, T's `created_at`) is neither input's. Before
/// the fix the carry was silent (no restamp), so O's own pre-merge record (same stamp,
/// later `created_at`) passed the manifest check when spliced over the saved one. (With
/// *equal* stamps the merged record is T's record at a pair O's own record used; that case
/// restamps too, see `item_meta.rs`.)
#[test]
fn guarantee_6_holds_when_only_created_at_is_carried() {
    let (mut o, mut t, id, _user_field, _pw_field) = two_devices_one_login();
    assert_eq!(o.get(id).unwrap().created_at, Some(1));
    let base_copy = t.get(id).unwrap().clone();
    assert_eq!(base_copy.modified_at, 1);

    // T: the base record with `created_at = 0`. `update` would restamp, so the copy is
    // re-inserted into an emptied twin at the base stamp under O's device id.
    t.delete(id, 1).unwrap();
    t.purge_tombstones_older_than(u64::MAX);
    let mut copy = base_copy;
    copy.created_at = Some(0);
    t.set_device_id(copy.device_id);
    t.insert(copy, 1);
    assert_eq!(
        t.get(id).unwrap().modified_at,
        1,
        "no restamp on a fresh id"
    );
    let file_t = t.serialize();

    // O: content untouched, stamp moved to 8.
    o.update(id, 8, |_| {}).unwrap();
    assert_eq!(o.get(id).unwrap().modified_at, 8);
    let file_o_before = o.serialize();

    let report = o.merge_from(&unlock(&file_t).unwrap()).unwrap();
    assert!(report.changed());
    assert_eq!(o.get(id).unwrap().created_at, Some(0));
    assert_eq!(o.get(id).unwrap().modified_at, 9);
    let file_o = o.serialize();

    assert_eq!(
        unlock(&splice(&file_o, &file_o_before, id)).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    assert_eq!(
        unlock(&splice(&file_o, &file_t, id)).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
    assert_eq!(
        unlock(&file_o).unwrap().get(id).unwrap().created_at,
        Some(0)
    );
}

/// The record-level variant (bug hunt 2026-11-27 N10). O and T hold the same item at the
/// same stamp in version 3 files and differ only in the record's plaintext unknown keys;
/// T's are the item winner's, so O takes them. That is a change of the persisted record at
/// a pair O's own record used, so it is stamped past both inputs: neither T's record nor
/// O's pre-merge record (same id, both at the old stamp) can replace the saved one. (Below
/// version 3 such keys are never merge input; see `record_extras_merge.rs`.)
#[test]
fn guarantee_6_holds_when_only_record_level_keys_are_taken() {
    let (dev_o, dev_t) = (Uuid::from_u128(0x0A), Uuid::from_u128(0x0B));
    let mut base = unstamped_vault();
    base.set_device_id(dev_o);
    let id = base.insert(sample_item(1, 1_000), 1_000);
    let stamp = base.get(id).unwrap().modified_at;
    // Version 3 first, then the keys, written by a holder of the vault key (an upgrade
    // drops keys a pre-3 file carried, and nothing below 3 binds them).
    let mut o = with_record_keys(&base, id, &[], dev_o);
    let mut t = with_record_keys(&base, id, &[], dev_t);
    o.upgrade_format(&pw(), 5_000).unwrap();
    t.upgrade_format(&pw(), 5_001).unwrap();
    let mut o = with_record_keys(&o, id, &[("x", 1)], dev_o);
    let t = with_record_keys(&t, id, &[("x", 2)], dev_t);
    let (pre_merge_o, file_t) = (o.serialize(), t.serialize());
    assert_eq!(&file_t[4..6], &[0, 3]);

    let report = o.merge_from(&unlock(&file_t).unwrap()).unwrap();
    assert_eq!(report.updated, 1);
    assert_eq!(o.get(id).unwrap().modified_at, stamp + 1);
    assert_eq!(record_keys(&o, id), [("x".to_owned(), 2)]);
    let file_o = o.serialize();

    for donor in [&file_t, &pre_merge_o] {
        assert_eq!(
            unlock(&splice(&file_o, donor, id)).unwrap_err(),
            VaultError::Tampered(TamperKind::Manifest)
        );
    }
    assert_eq!(record_keys(&unlock(&file_o).unwrap(), id).len(), 1);
}
