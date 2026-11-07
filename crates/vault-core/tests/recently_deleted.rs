//! Recently Deleted (02-core-api.md "Recently Deleted (2026-11-03)", 03-sync.md §5 "both
//! tombstones" row, 01-vault-format.md §4 `deleted_at`): `delete` keeps content, `recover`,
//! `delete_permanently`, `expire_deleted`, `deleted_items`, `Item::has_content`, and how a
//! strip or a recovery propagates through the merge.

mod common;

use ciborium::Value;
use common::*;
use vault_core::attachment::new_ref;
use vault_core::format::VaultFile;
use vault_core::vault::MergeReport;
use vault_core::{
    ExposeSecret, Field, FieldKind, FieldTombstone, HistoryEntry, Item, UnlockedVault, Uuid,
    VaultError,
};

fn dev_a() -> Uuid {
    Uuid::from_u128(0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA)
}

fn dev_b() -> Uuid {
    Uuid::from_u128(0xBBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB)
}

/// The item stamp [`loaded_vault`] leaves behind: inserted at 1_000, two attachment adds
/// (1_001, 1_002) and one removal (1_003).
const BASE: u64 = 1_003;

/// A vault on device A with one item carrying every kind of content (fields, history, an
/// attachment ref, all three removal-marker lists, extras), last stamped at [`BASE`].
fn loaded_vault() -> (UnlockedVault, Uuid) {
    let mut v = new_vault();
    v.set_device_id(dev_a());
    let mut item = sample_item(7, 1_000);
    item.favorite = true;
    item.history.push(HistoryEntry {
        value: secret("old-pw"),
        replaced_at: 900,
        field_id: None,
    });
    item.removed_history.push(800);
    item.removed_fields.push(FieldTombstone {
        id: Uuid::from_u128(0xF1E1D),
        removed_at: 950,
    });
    item.extras
        .push((Value::Text("x-plain".into()), Value::Integer(1.into())));
    let id = v.insert(item, 1_000);
    v.add_attachment_ref(id, new_ref("a.txt", 3, 1_000).unwrap(), 1_000)
        .unwrap();
    let r2 = new_ref("b.txt", 3, 1_000).unwrap();
    let r2_id = r2.id;
    v.add_attachment_ref(id, r2, 1_000).unwrap();
    v.remove_attachment_ref(id, r2_id, 1_001).unwrap();
    let item = v.get(id).unwrap();
    assert!(!item.fields.is_empty());
    assert!(!item.history.is_empty());
    assert_eq!(item.attachments.len(), 1);
    assert_eq!(item.removed_attachments.len(), 1);
    assert!(!item.removed_fields.is_empty());
    assert!(!item.removed_history.is_empty());
    assert!(!item.extras.is_empty());
    assert!(item.has_content());
    assert_eq!(item.modified_at, BASE);
    (v, id)
}

/// Device B holding a byte-copy of `a`.
fn peer(a: &UnlockedVault) -> UnlockedVault {
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    b
}

/// Same as `tests/merge.rs::converge`: two rounds, because a merge that takes the peer's
/// copy at an equal stamp bumps `modified_at` by one and the other side must see that.
fn converge(a: &mut UnlockedVault, b: &mut UnlockedVault) {
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert!(!a.merge_from(&b_snap).unwrap().changed(), "idempotent on A");
    assert!(!b.merge_from(&a_snap).unwrap().changed(), "idempotent on B");
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert_vaults_eq(a, b);
    assert!(
        !a.merge_from(&b_snap).unwrap().changed(),
        "idempotent on A (round 2)"
    );
    assert!(
        !b.merge_from(&a_snap).unwrap().changed(),
        "idempotent on B (round 2)"
    );
}

fn assert_stripped(item: &Item) {
    assert!(item.is_deleted());
    assert!(!item.has_content());
    assert!(item.fields.is_empty());
    assert!(item.history.is_empty());
    assert!(item.attachments.is_empty());
    assert!(item.removed_fields.is_empty());
    assert!(item.removed_attachments.is_empty());
    assert!(item.removed_history.is_empty());
    assert!(item.extras.is_empty());
}

fn is_malformed(e: &VaultError, needle: &str) -> bool {
    matches!(e, VaultError::Malformed(m) if m.contains(needle))
}

#[test]
fn has_content_checks_each_of_the_seven_lists() {
    let empty = Item::new("t", Uuid::nil(), 1);
    assert!(!empty.has_content(), "fresh item: no content");

    let mut i = empty.clone();
    i.fields
        .push(Field::new("u", FieldKind::Text, secret("v"), 1));
    assert!(i.has_content());

    let mut i = empty.clone();
    i.history.push(HistoryEntry {
        value: secret("v"),
        replaced_at: 1,
        field_id: None,
    });
    assert!(i.has_content());

    let mut i = empty.clone();
    i.attachments.push(new_ref("a", 1, 1).unwrap());
    assert!(i.has_content());

    let mut i = empty.clone();
    i.removed_fields.push(FieldTombstone {
        id: Uuid::nil(),
        removed_at: 1,
    });
    assert!(i.has_content());

    let mut i = empty.clone();
    i.removed_attachments.push(vault_core::AttachmentTombstone {
        id: Uuid::nil(),
        removed_at: 1,
    });
    assert!(i.has_content());

    let mut i = empty.clone();
    i.removed_history.push(1);
    assert!(i.has_content());

    let mut i = empty.clone();
    i.extras.push((Value::Text("k".into()), Value::Null));
    assert!(i.has_content());

    // Metadata alone is not content.
    let mut i = empty;
    i.title = "renamed".into();
    i.tags = vec!["t".into()];
    i.favorite = true;
    i.deleted_at = Some(5);
    assert!(!i.has_content());
}

#[test]
fn delete_keeps_content_and_lists_it_in_the_trash() {
    let (mut v, id) = loaded_vault();
    assert_eq!(v.deleted_items().count(), 0);
    let mut before = v.get(id).unwrap().clone();
    v.delete(id, 2_000).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(item.deleted_at, Some(2_000));
    assert_eq!(item.modified_at, 2_000);
    assert!(item.has_content(), "delete keeps the whole item");
    // Everything but the tombstone stamps is exactly what it was.
    before.deleted_at = Some(2_000);
    before.modified_at = 2_000;
    assert_item_eq(&before, item);
    assert_eq!(item.fields.len(), 5);
    assert_eq!(
        item.field("password").unwrap().value.expose_secret(),
        "p\u{e4}ss-7-hunter2"
    );
    assert_eq!(v.items().count(), 0, "not live");
    assert_eq!(v.items_including_deleted().count(), 1);
    let trash: Vec<Uuid> = v.deleted_items().map(|i| i.id).collect();
    assert_eq!(trash, vec![id]);

    // The content survives a save/unlock round-trip under the tombstone.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    assert!(u.get(id).unwrap().has_content());
    assert_eq!(u.deleted_items().count(), 1);
}

#[test]
fn recover_clears_deleted_at_and_restamps() {
    let (mut v, id) = loaded_vault();
    let mut before = v.get(id).unwrap().clone();
    v.delete(id, 2_000).unwrap();
    v.recover(id, 2_500).unwrap();
    let item = v.get(id).unwrap();
    assert!(!item.is_deleted());
    assert_eq!(item.deleted_at, None);
    assert_eq!(item.modified_at, 2_500);
    assert_eq!(item.device_id, dev_a());
    assert!(item.has_content());
    before.modified_at = 2_500;
    assert_item_eq(&before, item);
    assert_eq!(item.fields.len(), 5);
    assert_eq!(item.title, "Item 7 \u{1F511} caf\u{e9}");
    assert!(item.favorite);
    assert_eq!(v.items().count(), 1);
    assert_eq!(v.deleted_items().count(), 0);

    // Clock behind the tombstone: the stamp still strictly advances (stamp(now, previous)).
    v.delete(id, 3_000).unwrap();
    v.recover(id, 100).unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, 3_001);
    assert!(!v.get(id).unwrap().is_deleted());
}

#[test]
fn recover_errors() {
    let (mut v, id) = loaded_vault();
    let unknown = Uuid::from_u128(0xDEAD);
    let e = v.recover(unknown, 2_000).unwrap_err();
    assert!(is_malformed(&e, "unknown item"), "{e}");

    // Live item.
    let e = v.recover(id, 2_000).unwrap_err();
    assert!(is_malformed(&e, "is not deleted"), "{e}");
    assert_eq!(v.get(id).unwrap().modified_at, BASE, "untouched");

    // Stripped tombstone: nothing to recover.
    v.delete(id, 2_000).unwrap();
    v.delete_permanently(id, 2_100).unwrap();
    let e = v.recover(id, 2_200).unwrap_err();
    assert!(is_malformed(&e, "is not in the trash"), "{e}");
    let item = v.get(id).unwrap();
    assert!(item.is_deleted(), "still a tombstone");
    assert_eq!(item.modified_at, 2_100, "untouched");
}

#[test]
fn delete_permanently_strips_keeps_metadata_and_restamps() {
    let (mut v, id) = loaded_vault();
    let created = v.get(id).unwrap().created_at;
    v.update(id, 1_500, |i| i.tags.push("keep".into())).unwrap();
    v.delete(id, 2_000).unwrap();
    v.delete_permanently(id, 2_500).unwrap();
    let item = v.get(id).unwrap();
    assert_stripped(item);
    assert_eq!(item.id, id);
    assert_eq!(item.title, "Item 7 \u{1F511} caf\u{e9}");
    assert!(item.tags.contains(&"keep".to_owned()));
    assert!(item.favorite);
    assert_eq!(item.created_at, created);
    assert_eq!(item.deleted_at, Some(2_000), "deleted_at kept");
    assert_eq!(item.modified_at, 2_500, "restamped");
    assert_eq!(item.device_id, dev_a());
    assert_eq!(item.tags_modified_at, Some(1_500), "attribute stamps kept");
    assert_eq!(item.title_modified_at, Some(1_000));
    assert_eq!(v.deleted_items().count(), 0, "not in the trash any more");
    assert_eq!(v.items_including_deleted().count(), 1, "record stays");

    // Stripping again only restamps.
    v.delete_permanently(id, 2_600).unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, 2_600);
    assert_stripped(v.get(id).unwrap());

    // Clock behind: strictly advances.
    v.delete_permanently(id, 10).unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, 2_601);

    // Round-trips as a plain (pre-2026-11-03) tombstone.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    assert_stripped(u.get(id).unwrap());
}

#[test]
fn delete_permanently_errors() {
    let (mut v, id) = loaded_vault();
    let e = v
        .delete_permanently(Uuid::from_u128(0xDEAD), 2_000)
        .unwrap_err();
    assert!(is_malformed(&e, "unknown item"), "{e}");
    let e = v.delete_permanently(id, 2_000).unwrap_err();
    assert!(is_malformed(&e, "is not deleted"), "{e}");
    let item = v.get(id).unwrap();
    assert!(!item.is_deleted());
    assert!(item.has_content(), "live item untouched");
    assert_eq!(item.modified_at, BASE);
}

#[test]
fn delete_permanently_drops_record_extras() {
    let (mut v, id) = loaded_vault();
    v.delete(id, 2_000).unwrap();
    // Plant an unknown plaintext record-level key (01 §9) the way an older build preserves it.
    let bytes = rewrite(&v.serialize(), |f| {
        let rec = f.items.iter_mut().find(|r| r.id == id).unwrap();
        rec.extras
            .push((Value::Text("x-rec".into()), Value::Integer(9.into())));
    });
    let mut v = unlock(&bytes).unwrap();
    v.set_device_id(dev_a());
    let file = VaultFile::parse(&v.serialize()).unwrap();
    let rec = file.items.iter().find(|r| r.id == id).unwrap();
    assert_eq!(rec.extras.len(), 1, "record extras survive a plain save");

    v.delete_permanently(id, 2_500).unwrap();
    let file = VaultFile::parse(&v.serialize()).unwrap();
    let rec = file.items.iter().find(|r| r.id == id).unwrap();
    assert!(rec.extras.is_empty(), "stripping drops the record extras");
}

#[test]
fn expire_deleted_strips_only_old_content_tombstones_and_is_idempotent() {
    let mut v = new_vault();
    v.set_device_id(dev_a());
    let live = v.insert(sample_item(0, 1_000), 1_000);
    let old = v.insert(sample_item(1, 1_000), 1_000);
    let old2 = v.insert(sample_item(2, 1_000), 1_000);
    let fresh = v.insert(sample_item(3, 1_000), 1_000);
    let already = v.insert(sample_item(4, 1_000), 1_000);
    v.delete(old, 2_000).unwrap();
    v.delete(old2, 2_999).unwrap();
    v.delete(fresh, 3_000).unwrap();
    v.delete(already, 1_500).unwrap();
    v.delete_permanently(already, 1_600).unwrap();
    assert_eq!(v.deleted_items().count(), 3);

    // Strictly older than cutoff: 2_000 and 2_999 go, 3_000 stays, stripped one not counted.
    assert_eq!(v.expire_deleted(3_000, 5_000), 2);
    assert_stripped(v.get(old).unwrap());
    assert_eq!(v.get(old).unwrap().deleted_at, Some(2_000));
    assert_eq!(v.get(old).unwrap().modified_at, 5_000, "restamped");
    assert_eq!(v.get(old).unwrap().device_id, dev_a());
    assert_stripped(v.get(old2).unwrap());
    assert_eq!(v.get(old2).unwrap().modified_at, 5_000);
    assert!(v.get(fresh).unwrap().has_content(), "inside the window");
    assert_eq!(v.get(fresh).unwrap().modified_at, 3_000, "untouched");
    assert_eq!(v.get(already).unwrap().modified_at, 1_600, "not restamped");
    assert!(v.get(live).unwrap().has_content());
    assert!(!v.get(live).unwrap().is_deleted());
    assert_eq!(v.get(live).unwrap().modified_at, 1_000);
    let trash: Vec<Uuid> = v.deleted_items().map(|i| i.id).collect();
    assert_eq!(trash, vec![fresh]);

    // Idempotent.
    assert_eq!(v.expire_deleted(3_000, 6_000), 0);
    assert_eq!(v.get(old).unwrap().modified_at, 5_000, "no second restamp");
    // Window moves on.
    assert_eq!(v.expire_deleted(3_001, 6_000), 1);
    assert_stripped(v.get(fresh).unwrap());
    assert_eq!(v.expire_deleted(u64::MAX, 7_000), 0);
    assert_eq!(v.items_including_deleted().count(), 5, "no record dropped");
    assert_eq!(v.items().count(), 1);

    // Nothing to do on an empty vault or a vault with only live items.
    let mut e = new_vault();
    assert_eq!(e.expire_deleted(u64::MAX, 1), 0);
    e.insert(sample_item(0, 1), 1);
    assert_eq!(e.expire_deleted(u64::MAX, 2), 0);
}

#[test]
fn deleted_items_is_id_ordered_content_tombstones_only() {
    let mut v = new_vault();
    let ids: Vec<Uuid> = (0..4)
        .map(|i| v.insert(sample_item(i, 1_000), 1_000))
        .collect();
    for id in &ids[1..] {
        v.delete(*id, 2_000).unwrap();
    }
    v.delete_permanently(ids[2], 2_100).unwrap();
    let mut expected = vec![ids[1], ids[3]];
    expected.sort();
    let got: Vec<Uuid> = v.deleted_items().map(|i| i.id).collect();
    assert_eq!(got, expected);
    assert!(v.deleted_items().all(|i| i.is_deleted() && i.has_content()));
}

#[test]
fn merge_strip_beats_older_content_tombstone_both_directions() {
    // A and B both hold the content tombstone; A strips; the strip propagates to B.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    assert!(b.get(id).unwrap().has_content());
    a.delete_permanently(id, 2_500).unwrap();

    let report = b.merge_from(&unlock(&a.serialize()).unwrap()).unwrap();
    assert_eq!(
        report,
        MergeReport {
            added: 0,
            updated: 1,
            deleted: 0,
            unchanged: 0,
            header_updated: false
        }
    );
    assert_stripped(b.get(id).unwrap());
    assert_eq!(b.get(id).unwrap().modified_at, 2_500);
    assert_eq!(b.get(id).unwrap().device_id, dev_a());
    assert_eq!(b.deleted_items().count(), 0);

    // Other direction: the content side merges the stripped side (A merges B's old copy):
    // nothing changes on A.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    a.delete_permanently(id, 2_500).unwrap();
    let report = a.merge_from(&unlock(&b.serialize()).unwrap()).unwrap();
    assert!(!report.changed());
    assert_stripped(a.get(id).unwrap());
    converge(&mut a, &mut b);
    assert_stripped(a.get(id).unwrap());
    assert_stripped(b.get(id).unwrap());

    // Expiry is the same strip: it propagates too, even against a *later* re-delete on the
    // peer, as long as the expiry stamp is newer.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    b.delete(id, 2_200).unwrap(); // B re-deletes the tombstone: deleted_at 2_200, content kept
    assert_eq!(a.expire_deleted(2_001, 3_000), 1);
    converge(&mut a, &mut b);
    assert_stripped(a.get(id).unwrap());
    assert_eq!(a.get(id).unwrap().modified_at, 3_000);
    assert_eq!(a.get(id).unwrap().device_id, dev_a());
}

#[test]
fn merge_recovery_beats_older_tombstone_both_directions() {
    // A recovers; B still holds the tombstone with content.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    a.recover(id, 2_500).unwrap();

    // B merges A: the one-tombstone rule, deleted_at 2_000 < modified_at 2_500 -> live.
    let report = b.merge_from(&unlock(&a.serialize()).unwrap()).unwrap();
    assert_eq!(report.updated, 1);
    assert_eq!(report.deleted, 0);
    let item = b.get(id).unwrap();
    assert!(!item.is_deleted());
    assert!(item.has_content());
    assert_eq!(item.modified_at, 2_500);
    assert_eq!(item.fields.len(), 5);
    assert_eq!(b.items().count(), 1);

    // A merges B's stale tombstone: nothing changes.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    a.recover(id, 2_500).unwrap();
    assert!(
        !a.merge_from(&unlock(&b.serialize()).unwrap())
            .unwrap()
            .changed()
    );
    assert!(!a.get(id).unwrap().is_deleted());
    converge(&mut a, &mut b);
    assert!(!a.get(id).unwrap().is_deleted());
    assert!(a.get(id).unwrap().has_content());

    // B strips *after* the recovery stamp. The one-tombstone rule compares the tombstone's
    // `deleted_at`, not its `modified_at`, and a strip keeps `deleted_at` at the original
    // delete (2_000) < 2_500, so the recovery still wins. Pin that down.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    a.recover(id, 2_500).unwrap();
    b.delete_permanently(id, 2_600).unwrap();
    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    assert!(
        !item.is_deleted(),
        "deleted_at (2_000) < recovery stamp (2_500): the live item wins even though the strip is newer"
    );
    assert!(item.has_content());
    assert!(
        item.modified_at >= 2_600,
        "merge result modified_at = max(ours, theirs), plus the equal-stamp bump"
    );
    // A fresh delete on the recovered item is what removes it again.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    a.recover(id, 2_500).unwrap();
    b.recover(id, 2_400).unwrap();
    b.delete(id, 2_700).unwrap();
    converge(&mut a, &mut b);
    assert!(a.get(id).unwrap().is_deleted());
    assert_eq!(a.get(id).unwrap().deleted_at, Some(2_700));
}

#[test]
fn merge_tie_break_between_stripped_and_content_tombstones() {
    // Equal (modified_at, device_id) between a stripped and a content tombstone cannot arise
    // from a local strip (it always restamps past the copy it was made from and stamps its
    // own device). Build the tie by hand to document the path: the metadata tie-break falls
    // through to the greater canonical CBOR of the item payload, which is a symmetric total
    // order, so both sides pick the same copy, but *which* copy is content-dependent (a
    // longer byte string is not necessarily greater). The spec accepts that: content a merge
    // brings back into an already-expired tombstone is stripped again by the next sweep.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    b.set_device_id(dev_a()); // same device id on both sides for the tie
    a.delete_permanently(id, 2_500).unwrap();
    // B: a different mutation at the same stamp keeps its content.
    b.update(id, 2_500, |i| i.title = "zzz".into()).unwrap();
    assert_eq!(a.get(id).unwrap().modified_at, 2_500);
    assert_eq!(b.get(id).unwrap().modified_at, 2_500);
    assert_eq!(a.get(id).unwrap().device_id, b.get(id).unwrap().device_id);

    converge(&mut a, &mut b);
    let a_item = a.get(id).unwrap();
    assert!(
        a_item.is_deleted(),
        "a tie between tombstones stays a tombstone"
    );
    // Both sides agree on the winner; whichever it is, a sweep whose cutoff is past
    // deleted_at strips it again (or finds nothing to do), so the end state is a stripped
    // tombstone on both devices.
    let picked_content = a_item.has_content();
    assert_eq!(b.get(id).unwrap().has_content(), picked_content);
    let n_a = a.expire_deleted(2_001, 3_000);
    let n_b = b.expire_deleted(2_001, 3_000);
    assert_eq!(n_a, usize::from(picked_content));
    assert_eq!(n_b, usize::from(picked_content));
    assert_stripped(a.get(id).unwrap());
    assert_stripped(b.get(id).unwrap());

    // The device_id tie-break (greater device wins) is the one a real race can produce:
    // equal modified_at from two devices. The greater device's copy wins regardless of
    // whether it is the stripped one.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a); // dev_b > dev_a
    a.delete_permanently(id, 2_500).unwrap();
    b.update(id, 2_500, |i| i.title = "edited in trash".into())
        .unwrap();
    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    assert!(item.is_deleted());
    assert!(
        item.has_content(),
        "B (greater device_id) wins the tie: content comes back into A's stripped tombstone"
    );
    assert_eq!(item.title, "edited in trash");
    assert_eq!(
        a.expire_deleted(2_001, 3_000),
        1,
        "the sweep strips it again"
    );
    assert_eq!(b.expire_deleted(2_001, 3_000), 1);
    converge(&mut a, &mut b);
    assert_stripped(a.get(id).unwrap());
}

#[test]
fn delete_on_stripped_tombstone_is_a_noop_so_a_peer_recovery_survives() {
    // Plain: deleting the empty shell neither restamps nor errors; a content tombstone may
    // still be re-deleted.
    let (mut v, id) = loaded_vault();
    v.delete(id, 2_000).unwrap();
    v.delete(id, 2_100).unwrap();
    assert_eq!(
        v.get(id).unwrap().deleted_at,
        Some(2_100),
        "content tombstone re-deletes"
    );
    v.delete_permanently(id, 2_200).unwrap();
    v.delete(id, 9_000).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(
        item.deleted_at,
        Some(2_100),
        "stripped: deleted_at not moved"
    );
    assert_eq!(item.modified_at, 2_200, "stripped: not restamped");
    assert_stripped(item);

    // The race: A recovers at 2_500 while B holds the stripped copy and deletes it at 2_600.
    let (mut a, id) = loaded_vault();
    a.delete(id, 2_000).unwrap();
    a.delete_permanently(id, 2_100).unwrap();
    let mut b = peer(&a);
    // A gets the content back (a device tie-break with a content tombstone, 03 §5, can do
    // this): stand in for that by inserting the full item under the same id, which replaces
    // the shell and restamps past it, then recover it.
    let mut full = sample_item(7, 1_000);
    full.id = id;
    full.deleted_at = Some(2_300);
    a.insert(full, 2_300);
    assert!(a.get(id).unwrap().is_deleted());
    assert!(a.get(id).unwrap().has_content());
    a.recover(id, 2_500).unwrap();
    assert!(!a.get(id).unwrap().is_deleted());

    b.delete(id, 2_600).unwrap();
    assert_eq!(
        b.get(id).unwrap().deleted_at,
        Some(2_000),
        "no-op on the shell"
    );
    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    assert!(
        !item.is_deleted(),
        "recovery survives B's delete of the empty shell"
    );
    assert!(item.has_content());
    assert_eq!(item.fields.len(), 5);
    assert!(!b.get(id).unwrap().is_deleted());
}

#[test]
fn strip_and_expire_saturate_at_u64_max() {
    let mut v = new_vault();
    let mut item = sample_item(1, u64::MAX);
    item.history.push(HistoryEntry {
        value: secret("old"),
        replaced_at: u64::MAX,
        field_id: None,
    });
    let id = v.insert(item, u64::MAX);
    assert_eq!(v.get(id).unwrap().modified_at, u64::MAX);
    v.delete(id, u64::MAX).unwrap();
    assert_eq!(v.get(id).unwrap().deleted_at, Some(u64::MAX));
    assert!(v.get(id).unwrap().has_content());
    // deleted_at == u64::MAX is never < any cutoff.
    assert_eq!(v.expire_deleted(u64::MAX, u64::MAX), 0);
    assert!(v.get(id).unwrap().has_content());
    v.delete_permanently(id, u64::MAX).unwrap();
    let item = v.get(id).unwrap();
    assert_stripped(item);
    assert_eq!(item.modified_at, u64::MAX);
    assert_eq!(item.deleted_at, Some(u64::MAX));
    v.delete_permanently(id, u64::MAX).unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, u64::MAX);
    v.delete(id, u64::MAX).unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, u64::MAX);
    // Saturation residual (documented on `Item::is_trashed`): the strip could not restamp
    // past deleted_at, so the shell still reads as trashed and can be recovered as a live
    // title-only item. Below the top (see `other`) a stripped shell is not recoverable.
    assert!(v.get(id).unwrap().is_trashed());
    v.recover(id, u64::MAX).unwrap();
    let shell = v.get(id).unwrap();
    assert!(!shell.is_deleted());
    assert!(!shell.has_content());
    assert_eq!(shell.modified_at, u64::MAX);
    v.delete(id, u64::MAX).unwrap();
    assert_eq!(v.get(id).unwrap().deleted_at, Some(u64::MAX));

    // Content tombstone just below the top, swept with cutoff and now at the top.
    let other = v.insert(sample_item(2, 1_000), 1_000);
    v.delete(other, u64::MAX - 1).unwrap();
    assert_eq!(v.expire_deleted(u64::MAX, u64::MAX), 1);
    let item = v.get(other).unwrap();
    assert_stripped(item);
    assert_eq!(item.deleted_at, Some(u64::MAX - 1));
    assert_eq!(item.modified_at, u64::MAX);
    assert!(
        !item.is_trashed(),
        "restamped past deleted_at: out of the trash"
    );
    assert_eq!(
        v.expire_deleted(u64::MAX, u64::MAX),
        0,
        "idempotent at saturation"
    );
    assert_eq!(
        v.recover(other, u64::MAX).unwrap_err(),
        VaultError::Malformed(format!("item {other} is not in the trash"))
    );
    // Still a valid file.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
}

// ---------------------------------------------------------------------------------------------
// Title-only items (bug hunt 2026-11-06, L1): "in the trash" is `Item::is_trashed`, read off
// the stamps (`deleted_at` set and `modified_at <= deleted_at`, or content present), so an
// item that never had fields, history, attachments or markers lands in Recently Deleted too.
// ---------------------------------------------------------------------------------------------

/// `Item::new` plus tags and a favorite: what `vault add --title` with a field-less template
/// or a title-only CSV / KeePass row produces.
fn title_only(title: &str, now: u64) -> Item {
    let mut item = Item::new(title, dev_a(), now);
    item.tags = vec!["keep".into(), "work".into()];
    item.favorite = true;
    item
}

#[test]
fn title_only_item_round_trips_through_the_trash() {
    let mut v = new_vault();
    v.set_device_id(dev_a());
    let id = v.insert(title_only("Only a title", 100), 100);
    let live = v.get(id).unwrap();
    assert!(!live.has_content(), "nothing but metadata");
    assert!(!live.is_trashed(), "a live item is never in the trash");

    v.delete(id, 200).unwrap();
    let t = v.get(id).unwrap();
    assert_eq!(t.deleted_at, Some(200));
    assert_eq!(
        t.modified_at, 200,
        "delete leaves deleted_at == modified_at"
    );
    assert!(t.is_trashed());
    assert!(
        !t.has_content(),
        "still no content: the trash is not inferred from it"
    );
    assert_eq!(v.deleted_items().map(|i| i.id).collect::<Vec<_>>(), [id]);
    assert_eq!(v.items().count(), 0, "not live");

    // The tombstone keeps its place in the trash across a save/unlock round trip.
    let u = unlock(&v.serialize()).unwrap();
    assert!(u.get(id).unwrap().is_trashed());
    assert_eq!(u.deleted_items().count(), 1);

    v.recover(id, 300).unwrap();
    let r = v.get(id).unwrap();
    assert!(!r.is_deleted());
    assert!(!r.is_trashed());
    assert_eq!(r.modified_at, 300, "restamped past the tombstone");
    assert_eq!(r.device_id, dev_a());
    assert_eq!(r.title, "Only a title");
    assert_eq!(r.tags, ["keep", "work"]);
    assert!(r.favorite);
    assert!(r.fields.is_empty() && r.history.is_empty() && r.attachments.is_empty());
    assert_eq!(v.items().map(|i| i.id).collect::<Vec<_>>(), [id]);
    assert_eq!(v.deleted_items().count(), 0);
}

#[test]
fn cli_style_title_only_item_is_recoverable() {
    // `vault add --title Card --template card --tag bank`: `Item::new(title, device, now)`,
    // the user's tags, then the template tag; the card template adds no fields.
    let mut v = new_vault();
    v.set_device_id(dev_a());
    let now = 1_700_000_000_000;
    let mut item = Item::new("Card", v.device_id(), now);
    item.tags = vec!["bank".into()];
    if !item.tags.iter().any(|t| t.eq_ignore_ascii_case("card")) {
        item.tags.push("card".into());
    }
    let id = v.insert(item, now);
    assert!(!v.get(id).unwrap().has_content());

    v.delete(id, now + 1_000).unwrap();
    assert!(v.deleted_items().any(|i| i.id == id), "in Recently Deleted");
    v.recover(id, now + 2_000).unwrap();
    let r = v.get(id).unwrap();
    assert!(!r.is_deleted());
    assert_eq!(r.title, "Card");
    assert_eq!(r.tags, ["bank", "card"]);
    assert_eq!(r.modified_at, now + 2_000);
}

#[test]
fn title_only_tombstone_leaves_the_trash_only_when_stripped() {
    let mut v = new_vault();
    v.set_device_id(dev_a());
    let id = v.insert(title_only("t", 1_000), 1_000);
    v.delete(id, 2_000).unwrap();
    // Re-deleting a trashed tombstone moves deleted_at forward, like a content tombstone.
    v.delete(id, 2_100).unwrap();
    let t = v.get(id).unwrap();
    assert_eq!((t.deleted_at, t.modified_at), (Some(2_100), 2_100));
    assert!(t.is_trashed());

    // Inside the window: untouched.
    assert_eq!(v.expire_deleted(2_100, 5_000), 0, "strict cutoff");
    assert!(v.get(id).unwrap().is_trashed());
    // Past the window: the strip is a pure restamp here, and the restamp is what takes the
    // tombstone out of the trash.
    assert_eq!(v.expire_deleted(2_101, 5_000), 1);
    let s = v.get(id).unwrap();
    assert_eq!(s.deleted_at, Some(2_100), "strip never moves deleted_at");
    assert_eq!(s.modified_at, 5_000, "restamped");
    assert_eq!(s.device_id, dev_a());
    assert!(!s.is_trashed());
    assert_stripped(s);
    assert_eq!(s.title, "t");
    assert_eq!(s.tags, ["keep", "work"]);
    assert_eq!(v.deleted_items().count(), 0);
    assert_eq!(v.expire_deleted(u64::MAX, 6_000), 0, "idempotent");
    assert_eq!(v.get(id).unwrap().modified_at, 5_000, "no second restamp");
    // Nothing to recover; deleting the shell again is a no-op.
    let e = v.recover(id, 6_000).unwrap_err();
    assert!(is_malformed(&e, "is not in the trash"), "{e}");
    v.delete(id, 9_000).unwrap();
    let s = v.get(id).unwrap();
    assert_eq!((s.deleted_at, s.modified_at), (Some(2_100), 5_000), "no-op");

    // delete_permanently on a title-only tombstone, with the clock behind: the restamp is
    // still strictly past the tombstone (`stamp(now, previous)`), so the rule is exact.
    let id2 = v.insert(title_only("u", 1_000), 1_000);
    v.delete(id2, 2_000).unwrap();
    assert!(v.get(id2).unwrap().is_trashed());
    v.delete_permanently(id2, 10).unwrap();
    let s = v.get(id2).unwrap();
    assert_eq!((s.deleted_at, s.modified_at), (Some(2_000), 2_001));
    assert!(!s.is_trashed());
    assert!(v.recover(id2, 3_000).is_err());
    assert_eq!(v.items_including_deleted().count(), 2, "no record dropped");
}

#[test]
fn is_trashed_keeps_a_content_tombstone_whose_stamp_moved() {
    // The second half of the rule only matters for content-less tombstones: a tombstone with
    // content stays in the trash however its stamps move (here an attachment reference added
    // to the tombstone restamps it past deleted_at).
    let (mut v, id) = loaded_vault();
    v.delete(id, 2_000).unwrap();
    v.add_attachment_ref(id, new_ref("late.txt", 3, 2_500).unwrap(), 2_500)
        .unwrap();
    let t = v.get(id).unwrap();
    assert!(t.modified_at > t.deleted_at.unwrap());
    assert!(t.has_content());
    assert!(t.is_trashed());
    assert_eq!(v.deleted_items().count(), 1);
    v.recover(id, 3_000).unwrap();
    assert_eq!(v.get(id).unwrap().attachments.len(), 2);
}

#[test]
fn title_only_trash_propagates_like_a_content_tombstone() {
    // Delete on A reaches B's trash; B's recovery reaches A live with title and tags.
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(title_only("shared", 1_000), 1_000);
    let mut b = peer(&a);
    a.delete(id, 2_000).unwrap();
    let report = b.merge_from(&unlock(&a.serialize()).unwrap()).unwrap();
    assert_eq!(report.deleted, 1);
    let t = b.get(id).unwrap();
    assert_eq!((t.deleted_at, t.modified_at), (Some(2_000), 2_000));
    assert!(t.is_trashed(), "in B's trash after the merge");
    assert_eq!(b.deleted_items().count(), 1);

    b.recover(id, 2_500).unwrap();
    let report = a.merge_from(&unlock(&b.serialize()).unwrap()).unwrap();
    assert_eq!(report.updated, 1);
    let r = a.get(id).unwrap();
    assert!(!r.is_deleted());
    assert_eq!(r.title, "shared");
    assert_eq!(r.tags, ["keep", "work"]);
    converge(&mut a, &mut b);
    assert!(!a.get(id).unwrap().is_deleted() && !b.get(id).unwrap().is_deleted());

    // A strip propagates: the stripped copy is restamped past the trashed one.
    a.delete(id, 3_000).unwrap();
    b.merge_from(&unlock(&a.serialize()).unwrap()).unwrap();
    assert!(b.get(id).unwrap().is_trashed());
    a.delete_permanently(id, 3_500).unwrap();
    b.merge_from(&unlock(&a.serialize()).unwrap()).unwrap();
    let s = b.get(id).unwrap();
    assert!(s.is_deleted() && !s.is_trashed(), "stripped on B too");
    assert_eq!((s.deleted_at, s.modified_at), (Some(3_000), 3_500));
    assert_eq!(b.deleted_items().count(), 0);
    converge(&mut a, &mut b);
    assert!(!a.get(id).unwrap().is_trashed() && !b.get(id).unwrap().is_trashed());

    // Recovery beats a later strip (03 §5): the one-tombstone rule compares deleted_at, which
    // the strip does not move, so the title-only item survives on both devices.
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(title_only("raced", 1_000), 1_000);
    a.delete(id, 2_000).unwrap();
    let mut b = peer(&a);
    assert!(b.get(id).unwrap().is_trashed());
    a.recover(id, 2_500).unwrap();
    b.delete_permanently(id, 2_600).unwrap();
    converge(&mut a, &mut b);
    for v in [&a, &b] {
        let item = v.get(id).unwrap();
        assert!(!item.is_deleted(), "recovery survives the later strip");
        assert_eq!(item.title, "raced");
        assert_eq!(item.tags, ["keep", "work"]);
    }
    // Only a fresh delete after the recovery removes it again.
    b.delete(id, 2_700).unwrap();
    converge(&mut a, &mut b);
    assert!(a.get(id).unwrap().is_trashed() && b.get(id).unwrap().is_trashed());
}

#[test]
fn equal_stamp_tombstone_tie_is_the_documented_residual() {
    // An equal-stamp tie: both devices delete the same item at the same stamp (a delete
    // against an edit at the same stamp behaves alike). The both-tombstone rule picks B
    // (greater device id); on A the merge takes B's tombstone at an equal `modified_at` and
    // bumps it by one (03 §5), so A's copy reads `modified_at = deleted_at + 1`. For a
    // content tombstone that changes nothing (content keeps it in the trash); for a
    // title-only tombstone it is the one path that leaves the trash without a strip, and the
    // devices still converge. Documented in `Item::is_trashed`; this pins the behaviour.
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let plain = a.insert(title_only("plain", 1_000), 1_000);
    let rich = a.insert(sample_item(7, 1_000), 1_000);
    let mut b = peer(&a);
    for v in [&mut a, &mut b] {
        v.delete(plain, 2_000).unwrap();
        v.delete(rich, 2_000).unwrap();
    }
    a.merge_from(&unlock(&b.serialize()).unwrap()).unwrap();
    let p = a.get(plain).unwrap();
    assert_eq!(
        (p.deleted_at, p.modified_at, p.device_id),
        (Some(2_000), 2_001, dev_b())
    );
    assert!(
        !p.is_trashed(),
        "the equal-stamp bump reads as a strip on a content-less tombstone"
    );
    assert!(
        a.get(rich).unwrap().is_trashed(),
        "content keeps the rich one in the trash"
    );
    assert!(
        b.get(plain).unwrap().is_trashed(),
        "B's own copy is untouched"
    );
    converge(&mut a, &mut b);
    for v in [&a, &b] {
        assert!(!v.get(plain).unwrap().is_trashed());
        assert!(v.get(rich).unwrap().is_trashed());
        assert_eq!(
            v.get(plain).unwrap().title,
            "plain",
            "the shell still carries the title"
        );
    }
    assert_vaults_eq(&a, &b);
}

// ---------------------------------------------------------------------------------------------
// Legacy tombstones. `v2-trash-legacy.vault` holds what every tombstone was before
// 2026-11-03: the lists emptied at delete time and `deleted_at == modified_at` (the old
// `delete` stamped both at once). Under `is_trashed` such a shell is in the trash until the
// first sweep restamps it. The fixture was written by `regenerate_trash_legacy_fixture`, which
// reproduces that shape through `insert` (a tombstone inserted at its own stamp is not moved).
// ---------------------------------------------------------------------------------------------

const TRASH_LEGACY: &[u8] = include_bytes!("fixtures/v2-trash-legacy.vault");
const TL_AT: u64 = 1_698_000_000_000;
const TL_SHELL_A: u128 = 0x7A5A_0000_0000_0000_0000_0000_0000_0001;
const TL_SHELL_B: u128 = 0x7A5A_0000_0000_0000_0000_0000_0000_0002;
const TL_LIVE: u128 = 0x7A5A_0000_0000_0000_0000_0000_0000_0003;

#[test]
#[ignore = "regenerate the legacy-tombstone fixture (bytes change: fresh nonces)"]
fn regenerate_trash_legacy_fixture() {
    let mut v = new_vault();
    for (id, title, at) in [
        (TL_SHELL_A, "Old shell A", TL_AT),
        (TL_SHELL_B, "Old shell B", TL_AT + 1_000),
    ] {
        let mut shell = Item::new(title, device(), at);
        shell.id = Uuid::from_u128(id);
        shell.tags = vec!["legacy".into()];
        shell.deleted_at = Some(at);
        v.insert(shell, at);
        let s = v.get(Uuid::from_u128(id)).unwrap();
        assert_eq!((s.deleted_at, s.modified_at), (Some(at), at));
        assert!(!s.has_content());
    }
    let mut live = sample_item(1, TL_AT + 2_000);
    live.id = Uuid::from_u128(TL_LIVE);
    v.insert(live, TL_AT + 2_000);
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/v2-trash-legacy.vault"
        ),
        v.serialize(),
    )
    .unwrap();
}

#[test]
fn legacy_stripped_tombstones_are_in_the_trash_until_swept_once() {
    let a = Uuid::from_u128(TL_SHELL_A);
    let b = Uuid::from_u128(TL_SHELL_B);
    let mut v = unlock(TRASH_LEGACY).unwrap();
    v.set_device_id(dev_a());
    assert_eq!(v.items().count(), 1, "the live item");
    assert_eq!(v.items_including_deleted().count(), 3);
    let trash: Vec<Uuid> = v.deleted_items().map(|i| i.id).collect();
    assert_eq!(trash, [a, b], "both legacy shells, id order");
    for (id, title, at) in [(a, "Old shell A", TL_AT), (b, "Old shell B", TL_AT + 1_000)] {
        let s = v.get(id).unwrap();
        assert!(s.is_trashed() && !s.has_content());
        assert_eq!((s.deleted_at, s.modified_at), (Some(at), at));
        assert_eq!(s.title, title);
        assert_eq!(s.tags, ["legacy"]);
    }

    // One sweep restamps them once, and they are gone from the list.
    let now = TL_AT + 10_000;
    assert_eq!(v.expire_deleted(TL_AT + 5_000, now), 2);
    for (id, at) in [(a, TL_AT), (b, TL_AT + 1_000)] {
        let s = v.get(id).unwrap();
        assert!(!s.is_trashed());
        assert_eq!((s.deleted_at, s.modified_at), (Some(at), now));
        assert_eq!(s.device_id, dev_a());
        assert_eq!(
            s.title,
            if id == a {
                "Old shell A"
            } else {
                "Old shell B"
            }
        );
    }
    assert_eq!(v.deleted_items().count(), 0);
    assert_eq!(v.expire_deleted(TL_AT + 5_000, now + 1), 0, "idempotent");
    assert_eq!(v.get(a).unwrap().modified_at, now, "not restamped again");
    assert!(v.recover(a, now + 2).is_err());
    assert_eq!(v.items_including_deleted().count(), 3, "records kept");
    // The swept file still opens and keeps the shape.
    let again = unlock(&v.serialize()).unwrap();
    assert_eq!(again.deleted_items().count(), 0);
    assert_eq!(again.get(a).unwrap().modified_at, now);

    // Until swept, a legacy shell can be recovered as a live title-only item.
    let mut v = unlock(TRASH_LEGACY).unwrap();
    v.recover(a, TL_AT + 3_000).unwrap();
    let r = v.get(a).unwrap();
    assert!(!r.is_deleted());
    assert_eq!(r.title, "Old shell A");
    assert_eq!(r.tags, ["legacy"]);
    assert_eq!(r.modified_at, TL_AT + 3_000);
    assert_eq!(v.items().count(), 2);
}
