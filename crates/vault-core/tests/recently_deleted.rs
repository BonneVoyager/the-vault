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
    assert!(is_malformed(&e, "has no content"), "{e}");
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
    assert_eq!(
        v.recover(id, u64::MAX).unwrap_err(),
        VaultError::Malformed(format!("item {id} has no content"))
    );

    // Content tombstone just below the top, swept with cutoff and now at the top.
    let other = v.insert(sample_item(2, 1_000), 1_000);
    v.delete(other, u64::MAX - 1).unwrap();
    assert_eq!(v.expire_deleted(u64::MAX, u64::MAX), 1);
    let item = v.get(other).unwrap();
    assert_stripped(item);
    assert_eq!(item.deleted_at, Some(u64::MAX - 1));
    assert_eq!(item.modified_at, u64::MAX);
    assert_eq!(
        v.expire_deleted(u64::MAX, u64::MAX),
        0,
        "idempotent at saturation"
    );
    // Still a valid file.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
}
