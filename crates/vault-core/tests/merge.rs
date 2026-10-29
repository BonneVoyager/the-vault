//! `merge_from` (03-sync.md §5) and guarantee 9.

mod common;

use common::*;
use vault_core::vault::MergeReport;
use vault_core::vault::merge::item_eq;
use vault_core::{
    ExposeSecret, Field, FieldKind, HistoryEntry, Item, ItemKind, KdfParams, UnlockedVault, Uuid,
    VaultError,
};

fn dev_a() -> Uuid {
    Uuid::from_u128(0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA)
}

fn dev_b() -> Uuid {
    Uuid::from_u128(0xBBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB)
}

/// Two "devices" holding the same vault with `n` items at t=1000 (A's device id stamped).
fn two_devices(n: u64) -> (UnlockedVault, UnlockedVault, Vec<Uuid>) {
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let ids: Vec<Uuid> = (0..n)
        .map(|i| a.insert(sample_item(i, 1_000), 1_000))
        .collect();
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    assert_vaults_eq(&a, &b);
    (a, b, ids)
}

fn value(v: &UnlockedVault, id: Uuid, field: &str) -> String {
    v.get(id)
        .unwrap()
        .field(field)
        .unwrap()
        .value
        .expose_secret()
        .clone()
}

#[test]
fn guarantee_9_delete_then_merge_older_copy_stays_deleted() {
    let (mut a, b, ids) = two_devices(3);
    let id = ids[1];
    a.delete(id, 2_000).unwrap();
    let report = a.merge_from(&b).unwrap();
    assert_eq!(
        report,
        MergeReport {
            added: 0,
            updated: 0,
            deleted: 0,
            unchanged: 3
        }
    );
    assert!(!report.changed());
    assert!(a.get(id).unwrap().is_deleted());
    assert_eq!(a.items().count(), 2);

    // Other direction: the older live copy learns about the tombstone.
    let mut b = b;
    let report = b.merge_from(&a).unwrap();
    assert_eq!(report.deleted, 1);
    assert_eq!(report.unchanged, 2);
    assert!(report.changed());
    assert!(b.get(id).unwrap().is_deleted());
    assert_eq!(b.get(id).unwrap().deleted_at, Some(2_000));
    assert_eq!(b.get(id).unwrap().modified_at, 2_000);
    assert_vaults_eq(&a, &b);

    // Delete with `now` equal to the live item's modified_at: the tombstone is stamped
    // strictly later (1001) and wins.
    let (mut a, mut b, ids) = two_devices(1);
    a.delete(ids[0], 1_000).unwrap();
    assert_eq!(a.get(ids[0]).unwrap().deleted_at, Some(1_001));
    b.merge_from(&a).unwrap();
    assert!(b.get(ids[0]).unwrap().is_deleted());
}

#[test]
fn edit_after_delete_resurrects() {
    let (mut a, mut b, ids) = two_devices(2);
    let id = ids[0];
    a.delete(id, 2_000).unwrap();
    b.set_field(id, "username", secret("resurrected"), 3_000)
        .unwrap();

    let report = a.merge_from(&b).unwrap();
    assert_eq!(report.updated, 1);
    assert_eq!(report.deleted, 0);
    assert_eq!(report.unchanged, 1);
    let item = a.get(id).unwrap();
    assert!(!item.is_deleted());
    assert_eq!(item.modified_at, 3_000);
    assert_eq!(item.device_id, dev_b());
    assert_eq!(value(&a, id, "username"), "resurrected");
    assert_eq!(a.items().count(), 2);

    // The tombstone side, merged the other way, is unchanged (already live & newer).
    let report = b.merge_from(&a).unwrap();
    assert!(!report.changed());
    assert_vaults_eq(&a, &b);
}

#[test]
fn field_level_merge_is_commutative() {
    let (mut a, mut b, ids) = two_devices(2);
    let id = ids[0];
    a.set_field(id, "username", secret("alice-new"), 10_000)
        .unwrap();
    b.set_field(id, "password", secret("bob-new-pw"), 11_000)
        .unwrap();

    let a_snapshot = unlock(&a.serialize()).unwrap();
    let b_snapshot = unlock(&b.serialize()).unwrap();

    let ra = a.merge_from(&b_snapshot).unwrap();
    let rb = b.merge_from(&a_snapshot).unwrap();
    assert_eq!(ra.updated, 1);
    assert_eq!(rb.updated, 1);
    assert_eq!(ra.unchanged, 1);
    // Content is identical after one round; B's record timestamp moved to 11001 because its
    // content changed while max(modified_at) was already its own 11000.
    assert_eq!(a.get(id).unwrap().modified_at, 11_000);
    assert_eq!(b.get(id).unwrap().modified_at, 11_001);
    let b_round2 = unlock(&b.serialize()).unwrap();
    assert_eq!(
        a.merge_from(&b_round2).unwrap().updated,
        1,
        "A picks up the bump"
    );

    assert_item_eq(a.get(id).unwrap(), b.get(id).unwrap());
    let item = a.get(id).unwrap();
    assert_eq!(value(&a, id, "username"), "alice-new");
    assert_eq!(value(&a, id, "password"), "bob-new-pw");
    assert_eq!(item.field("username").unwrap().modified_at, 10_000);
    assert_eq!(item.field("password").unwrap().modified_at, 11_000);
    assert_eq!(item.modified_at, 11_001);
    assert_eq!(item.device_id, dev_b(), "metadata from the newer side");
    assert_eq!(
        item.history.len(),
        2,
        "B's password history came across (plus the sample entry)"
    );
    assert_eq!(item.history[0].replaced_at, 11_000);
    assert_eq!(item.fields.len(), 5);
    assert_vaults_eq(&a, &b);
}

#[test]
fn metadata_from_newer_side_tie_breaks_on_device_id() {
    // Same modified_at on both sides, different content: the greater device_id wins.
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    a.update(id, 5_000, |i| {
        i.title = "from A".into();
        i.favorite = true;
        i.tags = vec!["a".into()];
        i.fields[0].value = secret("A-user");
    })
    .unwrap();
    b.update(id, 5_000, |i| {
        i.title = "from B".into();
        i.favorite = false;
        i.tags = vec!["b".into()];
        i.fields[0].value = secret("B-user");
    })
    .unwrap();
    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    assert_eq!(item.title, "from B");
    assert_eq!(item.device_id, dev_b());
    assert_eq!(item.tags, vec!["b".to_owned()]);
    assert_eq!(value(&a, id, "username"), "B-user");
    assert_eq!(item.field("username").unwrap().modified_at, 5_000);

    // Newer modified_at beats a greater device_id.
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    a.update(id, 6_000, |i| i.title = "from A".into()).unwrap();
    b.update(id, 5_000, |i| i.title = "from B".into()).unwrap();
    converge(&mut a, &mut b);
    assert_eq!(a.get(id).unwrap().title, "from A");
    assert_eq!(a.get(id).unwrap().device_id, dev_a());
}

#[test]
fn field_present_on_one_side_only_is_taken() {
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    a.update(id, 2_000, |i| {
        i.fields
            .push(Field::new("pin", FieldKind::Number, secret("0000"), 2_000));
    })
    .unwrap();
    b.update(id, 3_000, |i| {
        i.fields.retain(|f| f.name != "notes"); // field removal is not tracked
        i.fields
            .push(Field::new("extra", FieldKind::Text, secret("e"), 3_000));
    })
    .unwrap();
    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    let names: Vec<&str> = item.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "username", "password", "totp", "url", "extra", "notes", "pin"
        ],
        "winner (B) order first, then A-only fields in A's order"
    );
    assert_eq!(value(&a, id, "pin"), "0000");
    assert_eq!(value(&a, id, "extra"), "e");
    assert_eq!(
        item.modified_at, 3_001,
        "B's content changed at max 3000 -> 3001"
    );
}

#[test]
fn history_union_and_cap() {
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    for i in 0..7u64 {
        a.set_field(id, "password", secret(format!("a{i}")), 2_000 + i)
            .unwrap();
    }
    for i in 0..7u64 {
        b.set_field(id, "password", secret(format!("b{i}")), 2_100 + i)
            .unwrap();
    }
    // One entry shared verbatim on both sides must not be duplicated.
    a.update(id, 2_000, |i| {
        i.history.push(HistoryEntry {
            value: secret("shared"),
            replaced_at: 1_999,
        });
    })
    .unwrap();
    b.update(id, 2_000, |i| {
        i.history.push(HistoryEntry {
            value: secret("shared"),
            replaced_at: 1_999,
        });
    })
    .unwrap();
    converge(&mut a, &mut b);
    let h = &a.get(id).unwrap().history;
    assert_eq!(h.len(), 10);
    assert!(h.windows(2).all(|w| w[0].replaced_at >= w[1].replaced_at));
    assert_eq!(h[0].replaced_at, 2_106);
    let values: Vec<&str> = h.iter().map(|e| e.value.expose_secret().as_str()).collect();
    // 7 from b (2100..2106) are the newest, then a's losing *current* password a6 (recorded
    // at its own modified_at 2006, tie with a5@2006 broken by value), then a4.
    assert_eq!(
        values,
        vec![
            "b5",
            "b4",
            "b3",
            "b2",
            "b1",
            "b0",
            "p\u{e4}ss-0-hunter2",
            "a5",
            "a6",
            "a4"
        ]
    );
    assert!(
        !values.contains(&"shared"),
        "oldest entries fall off the cap"
    );

    // Smaller union: dedupe is exact on (value, replaced_at).
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    a.set_field(id, "password", secret("x"), 2_000).unwrap();
    b.set_field(id, "password", secret("x"), 2_000).unwrap();
    b.set_field(id, "password", secret("y"), 2_001).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    let h = &a.get(id).unwrap().history;
    assert_eq!(h.len(), 3, "x@2001, x@2000 and the sample entry @900");
    assert_eq!(h[0].value.expose_secret(), "x");
    assert_eq!(h[0].replaced_at, 2_001);
    assert_eq!(h[1].replaced_at, 2_000);
}

#[test]
fn absent_items_and_tombstones_are_added() {
    let (mut a, mut b, ids) = two_devices(2);
    let new_in_b = b.insert(sample_item(9, 5_000), 5_000);
    let dead_in_b = b.insert(sample_item(10, 5_000), 5_000);
    b.delete(dead_in_b, 5_001).unwrap();
    let new_in_a = a.insert(sample_item(11, 5_000), 5_000);

    let report = a.merge_from(&b).unwrap();
    assert_eq!(
        report,
        MergeReport {
            added: 2,
            updated: 0,
            deleted: 0,
            unchanged: 3
        },
        "two ids new to A; A's own extra item counts as unchanged"
    );
    assert_item_eq(a.get(new_in_b).unwrap(), b.get(new_in_b).unwrap());
    assert!(a.get(dead_in_b).unwrap().is_deleted());
    assert_eq!(a.items().count(), 4);
    assert!(b.get(new_in_a).is_none());
    assert_eq!(a.get(ids[0]).unwrap().modified_at, 1_000);
}

#[test]
fn merge_is_idempotent_and_identical_copies_are_unchanged() {
    let (mut a, mut b, ids) = two_devices(4);
    let r = a.merge_from(&b).unwrap();
    assert_eq!(r.unchanged, 4);
    assert!(!r.changed());

    a.set_field(ids[0], "username", secret("u"), 2_000).unwrap();
    b.set_field(ids[0], "password", secret("p"), 2_001).unwrap();
    b.delete(ids[1], 2_002).unwrap();
    a.update(ids[2], 2_003, |i| i.title = "t".into()).unwrap();
    b.insert(sample_item(20, 2_004), 2_004);

    let b_snap = unlock(&b.serialize()).unwrap();
    let first = a.merge_from(&b_snap).unwrap();
    assert_eq!(
        first,
        MergeReport {
            added: 1,
            updated: 1,
            deleted: 1,
            unchanged: 2
        }
    );
    let a_after_first = unlock(&a.serialize()).unwrap();
    let second = a.merge_from(&b_snap).unwrap();
    assert!(!second.changed(), "{second:?}");
    assert_eq!(second.unchanged, 5);
    assert_vaults_eq(&a, &a_after_first);

    // Commutativity on the whole vault (second round carries the +1 bumps back).
    let a_snap = unlock(&a.serialize()).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert!(!b.merge_from(&a_snap).unwrap().changed());
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    assert_vaults_eq(&a, &b);
    assert!(!a.merge_from(&b_snap).unwrap().changed());
    assert!(!b.merge_from(&a_snap).unwrap().changed());
}

#[test]
fn vault_id_mismatch_is_an_error() {
    let mut a = new_vault();
    let mut other = UnlockedVault::create(&pw(), KdfParams::for_tests(), device());
    other.insert(sample_item(1, 1), 1);
    let before = a.items_including_deleted().count();
    assert_eq!(
        a.merge_from(&other).unwrap_err(),
        VaultError::Malformed("vault_id mismatch".into())
    );
    assert_eq!(
        a.items_including_deleted().count(),
        before,
        "nothing merged"
    );
}

#[test]
fn round_trip_after_merge() {
    let (mut a, mut b, ids) = two_devices(5);
    a.set_field(ids[0], "password", secret("new"), 2_000)
        .unwrap();
    b.delete(ids[1], 2_001).unwrap();
    b.update(ids[2], 2_002, |i| {
        i.tags.push("merged".into());
        i.fields
            .push(Field::new("extra", FieldKind::Text, secret("e"), 2_002));
    })
    .unwrap();
    a.delete(ids[3], 2_003).unwrap();
    b.set_field(ids[3], "username", secret("back"), 2_004)
        .unwrap();
    b.insert(
        Item::new(ItemKind::Note, "fresh", Uuid::nil(), 2_005),
        2_005,
    );

    let b_snap = unlock(&b.serialize()).unwrap();
    let report = a.merge_from(&b_snap).unwrap();
    assert!(report.changed());
    assert_eq!(report.added, 1);
    assert_eq!(report.deleted, 1);
    assert_eq!(report.updated, 2, "tags edit and resurrection");

    let bytes = a.serialize();
    let u = unlock(&bytes).unwrap();
    assert_vaults_eq(&a, &u);
    assert_eq!(u.items().count(), 5);
    assert!(u.get(ids[1]).unwrap().is_deleted());
    assert!(!u.get(ids[3]).unwrap().is_deleted());
    assert_eq!(value(&u, ids[3], "username"), "back");
    assert_eq!(value(&u, ids[0], "password"), "new");
    for (x, y) in a.items_including_deleted().zip(u.items_including_deleted()) {
        assert!(item_eq(x, y));
    }
}

// ---------------------------------------------------------------------------------------------
// Clock-skew safety (P4a security review): local mutations made with a `now` behind the item's
// own timestamps must still win against the untouched copy they were made from.
// ---------------------------------------------------------------------------------------------

/// Merge both ways from serialized snapshots, twice (a content change that leaves
/// `max(modified_at)` equal to ours is stamped +1, which the peer picks up on the next round),
/// and assert both sides converge and the merge is idempotent.
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

#[test]
fn skewed_delete_stays_deleted_in_both_directions() {
    let (mut a, mut b, ids) = two_devices(2);
    let id = ids[0];
    // A's clock is behind: the item was last modified at 1000, A deletes "at" 400.
    a.delete(id, 400).unwrap();
    assert_eq!(a.get(id).unwrap().deleted_at, Some(1_001));
    assert_eq!(a.get(id).unwrap().modified_at, 1_001);

    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    let ra = a.merge_from(&b_snap).unwrap();
    assert!(!ra.changed(), "untouched peer copy does not resurrect");
    assert!(a.get(id).unwrap().is_deleted());

    let rb = b.merge_from(&a_snap).unwrap();
    assert_eq!(rb.deleted, 1);
    assert!(b.get(id).unwrap().is_deleted());
    assert_vaults_eq(&a, &b);
}

#[test]
fn skewed_set_field_and_update_survive_merge() {
    let (mut a, mut b, ids) = two_devices(2);
    let id = ids[0];
    // Fields were stamped 1000 (password 999); A's clock says 300.
    a.set_field(id, "password", secret("skewed-pw"), 300)
        .unwrap();
    a.update(id, 200, |i| {
        i.fields[0].value = secret("skewed-user"); // username, timestamp not bumped by caller
        i.title = "skewed title".into();
    })
    .unwrap();
    let item = a.get(id).unwrap();
    assert_eq!(
        item.field("password").unwrap().modified_at,
        1_000,
        "999 + 1"
    );
    assert_eq!(
        item.field("username").unwrap().modified_at,
        1_001,
        "1000 + 1"
    );
    assert_eq!(item.modified_at, 1_002, "set_field -> 1001, update -> 1002");
    assert_eq!(item.history[0].replaced_at, 1_000);

    converge(&mut a, &mut b);
    for v in [&a, &b] {
        assert_eq!(value(v, id, "password"), "skewed-pw");
        assert_eq!(value(v, id, "username"), "skewed-user");
        assert_eq!(v.get(id).unwrap().title, "skewed title");
        assert!(!v.get(id).unwrap().is_deleted());
    }
}

#[test]
fn both_tombstones_converge() {
    let (mut a, mut b, ids) = two_devices(3);
    let id = ids[0];
    a.delete(id, 2_000).unwrap();
    b.delete(id, 3_000).unwrap();
    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    assert!(item.is_deleted());
    assert_eq!(item.deleted_at, Some(3_000), "newer tombstone wins");
    assert_eq!(item.modified_at, 3_000);
    assert_eq!(item.device_id, dev_b());

    // Equal timestamps: device_id tie-break, both sides agree.
    let id = ids[1];
    a.delete(id, 4_000).unwrap();
    b.delete(id, 4_000).unwrap();
    converge(&mut a, &mut b);
    assert_eq!(a.get(id).unwrap().device_id, dev_b());
    assert_eq!(a.items().count(), 1);
}

#[test]
fn update_on_tombstone_converges() {
    let (mut a, mut b, ids) = two_devices(2);
    let id = ids[0];
    a.delete(id, 2_000).unwrap();
    // Editing a tombstone in place keeps it a tombstone (deleted_at untouched by `update`).
    a.update(id, 2_500, |i| i.title = "edited tombstone".into())
        .unwrap();
    let item = a.get(id).unwrap();
    assert!(item.is_deleted());
    assert_eq!(item.modified_at, 2_500);

    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    assert!(item.is_deleted());
    assert_eq!(item.title, "edited tombstone");
    assert_eq!(item.modified_at, 2_500);

    // B edits the live copy *later* than the tombstone edit: it resurrects on both sides.
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    a.delete(id, 2_000).unwrap();
    a.update(id, 2_500, |i| i.title = "t".into()).unwrap();
    b.set_field(id, "username", secret("alive"), 2_600).unwrap();
    converge(&mut a, &mut b);
    assert!(!a.get(id).unwrap().is_deleted());
    assert_eq!(value(&a, id, "username"), "alive");

    // ... and *earlier* than the tombstone's deleted_at: stays deleted on both sides.
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    b.set_field(id, "username", secret("too-late"), 1_500)
        .unwrap();
    a.delete(id, 2_000).unwrap();
    a.update(id, 2_500, |i| i.title = "t".into()).unwrap();
    converge(&mut a, &mut b);
    assert!(a.get(id).unwrap().is_deleted());
}

#[test]
fn password_conflict_loser_lands_in_history_on_both_sides() {
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    a.set_field(id, "password", secret("from-A"), 5_000)
        .unwrap();
    b.set_field(id, "password", secret("from-B"), 6_000)
        .unwrap();
    // Non-password conflict: loser is simply dropped.
    a.set_field(id, "username", secret("uA"), 5_000).unwrap();
    b.set_field(id, "username", secret("uB"), 6_000).unwrap();

    converge(&mut a, &mut b);
    for v in [&a, &b] {
        let item = v.get(id).unwrap();
        assert_eq!(value(v, id, "password"), "from-B");
        assert_eq!(value(v, id, "username"), "uB");
        let entries: Vec<(&str, u64)> = item
            .history
            .iter()
            .map(|h| (h.value.expose_secret().as_str(), h.replaced_at))
            .collect();
        assert!(
            entries.contains(&("from-A", 5_000)),
            "losing current password recorded at its own modified_at: {entries:?}"
        );
        // Original value replaced on each side at its own time: deduped to two entries, plus
        // the sample item's seeded entry.
        assert_eq!(
            entries,
            vec![
                ("p\u{e4}ss-0-hunter2", 6_000),
                ("from-A", 5_000),
                ("p\u{e4}ss-0-hunter2", 5_000),
                ("old-0", 900),
            ]
        );
        assert!(
            !entries.iter().any(|(v, _)| *v == "uA"),
            "non-password losers are not recorded"
        );
    }

    // Equal values on both sides are not a conflict and leave no history entry.
    let (mut a, mut b, ids) = two_devices(1);
    let id = ids[0];
    a.set_field(id, "password", secret("same"), 5_000).unwrap();
    b.set_field(id, "password", secret("same"), 6_000).unwrap();
    converge(&mut a, &mut b);
    assert!(
        !a.get(id)
            .unwrap()
            .history
            .iter()
            .any(|h| h.value.expose_secret() == "same")
    );
}

#[test]
fn merge_that_changes_content_advances_modified_at_and_defeats_rollback() {
    use vault_core::format::VaultFile;
    use vault_core::{TamperKind, VaultError};

    let (mut a, mut b, ids) = two_devices(2);
    let id = ids[0];
    // Ours: username@10000, item@10000. Theirs: password@9000, item@9000. The merge takes
    // theirs' password but max(modified_at) stays at ours' 10000.
    a.set_field(id, "username", secret("alice"), 10_000)
        .unwrap();
    b.set_field(id, "password", secret("bob-pw"), 9_000)
        .unwrap();
    let pre_merge = a.serialize();
    let b_snap = unlock(&b.serialize()).unwrap();

    let report = a.merge_from(&b_snap).unwrap();
    assert_eq!(report.updated, 1);
    let item = a.get(id).unwrap();
    assert_eq!(value(&a, id, "password"), "bob-pw");
    assert_eq!(value(&a, id, "username"), "alice");
    assert_eq!(
        item.modified_at, 10_001,
        "content changed, so the record timestamp moved"
    );

    // Splice the genuine pre-merge record for this id into the post-merge file: it decrypts
    // under its own AAD, so only the manifest cross-check can catch the rollback.
    let post_merge = a.serialize();
    let old_rec = VaultFile::parse(&pre_merge)
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.id == id)
        .unwrap();
    let t = rewrite(&post_merge, |f| {
        *f.items.iter_mut().find(|r| r.id == id).unwrap() = old_rec;
    });
    assert_eq!(
        unlock(&t).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );

    // Both sides still converge: B takes the max on its next merge.
    let a_snap = unlock(&post_merge).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert_vaults_eq(&a, &b);
    assert!(!a.merge_from(&b_snap).unwrap().changed());
    let b_snap = unlock(&b.serialize()).unwrap();
    assert!(!a.merge_from(&b_snap).unwrap().changed());

    // A merge whose result keeps ours' content untouched does not move the timestamp.
    let (mut a, b, ids) = two_devices(1);
    a.set_field(ids[0], "username", secret("x"), 5_000).unwrap();
    assert!(!a.merge_from(&b).unwrap().changed());
    assert_eq!(a.get(ids[0]).unwrap().modified_at, 5_000);
}
