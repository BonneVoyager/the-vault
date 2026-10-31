//! Removable history entries: `remove_history_entry`, `clear_history`, the `removed_history`
//! stamp list (01 §4) and its merge rule (03 §5).

mod common;

use ciborium::Value;
use common::*;
use vault_core::vault::HISTORY_CAP;
use vault_core::vault::merge::item_eq;
use vault_core::{ExposeSecret, HistoryEntry, UnlockedVault, Uuid, VaultError, format};

/// A vault with one item whose password was changed `n` times at 2_001..=2_000+n, so history
/// holds `n` entries stamped 2_001..=2_000+n (newest first) plus none from the sample.
fn vault_with_history(n: u64) -> (UnlockedVault, Uuid) {
    let mut v = new_vault();
    let id = v.insert(sample_item(1, 1_000), 1_000);
    for i in 1..=n {
        v.set_field(id, "password", secret(format!("pw-{i}")), 2_000 + i)
            .unwrap();
    }
    (v, id)
}

fn stamps(v: &UnlockedVault, id: Uuid) -> Vec<u64> {
    v.get(id)
        .unwrap()
        .history
        .iter()
        .map(|h| h.replaced_at)
        .collect()
}

fn two_copies(v: &UnlockedVault) -> (UnlockedVault, UnlockedVault) {
    let bytes = v.serialize();
    let mut a = unlock(&bytes).unwrap();
    let mut b = unlock(&bytes).unwrap();
    a.set_device_id(Uuid::from_u128(0xA));
    b.set_device_id(Uuid::from_u128(0xB));
    (a, b)
}

fn plain_map(v: &UnlockedVault, id: Uuid) -> Entries {
    let plain = format::encode_item_plain(v.get(id).unwrap());
    let Value::Map(entries) = ciborium::from_reader(plain.as_slice()).unwrap() else {
        panic!("ItemPlain is a map")
    };
    entries
}

type Entries = Vec<(Value, Value)>;

fn key(entries: &[(Value, Value)], k: &str) -> Option<Value> {
    entries
        .iter()
        .find(|(x, _)| x == &Value::Text(k.into()))
        .map(|(_, v)| v.clone())
}

#[test]
fn remove_history_entry_records_stamp_and_restamps() {
    let (mut v, id) = vault_with_history(3);
    assert_eq!(stamps(&v, id), vec![2_003, 2_002, 2_001]);
    assert!(v.get(id).unwrap().removed_history.is_empty());

    v.remove_history_entry(id, 2_002, 5_000).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(stamps(&v, id), vec![2_003, 2_001]);
    assert_eq!(item.removed_history, vec![2_002]);
    assert_eq!(item.modified_at, 5_000, "restamped");
    assert_eq!(item.device_id, device());
    assert_eq!(
        item.field("password").unwrap().modified_at,
        2_003,
        "field untouched"
    );

    // Clock behind: the item still strictly advances.
    v.remove_history_entry(id, 2_001, 100).unwrap();
    assert_eq!(stamps(&v, id), vec![2_003]);
    assert_eq!(v.get(id).unwrap().removed_history, vec![2_002, 2_001]);
    assert_eq!(v.get(id).unwrap().modified_at, 5_001);

    // Unknown stamp / unknown item are Malformed and change nothing.
    let before = v.get(id).unwrap().clone();
    let err = v.remove_history_entry(id, 2_002, 6_000).unwrap_err();
    assert!(
        matches!(&err, VaultError::Malformed(m) if m.contains("unknown history entry")),
        "{err:?}"
    );
    assert!(item_eq(&before, v.get(id).unwrap()));
    assert!(matches!(
        v.remove_history_entry(Uuid::nil(), 2_003, 6_000),
        Err(VaultError::Malformed(_))
    ));

    // Two entries with the same stamp (a merge can produce them) go together.
    v.update(id, 6_000, |item| {
        item.history.push(HistoryEntry {
            value: secret("twin"),
            replaced_at: 2_003,
        });
    })
    .unwrap();
    assert_eq!(stamps(&v, id), vec![2_003, 2_003]);
    v.remove_history_entry(id, 2_003, 7_000).unwrap();
    assert!(v.get(id).unwrap().history.is_empty());
    assert_eq!(
        v.get(id).unwrap().removed_history,
        vec![2_003, 2_002, 2_001]
    );
}

#[test]
fn clear_history_records_every_stamp_and_is_idempotent() {
    let (mut v, id) = vault_with_history(4);
    v.clear_history(id, 5_000).unwrap();
    let item = v.get(id).unwrap();
    assert!(item.history.is_empty());
    assert_eq!(item.removed_history, vec![2_004, 2_003, 2_002, 2_001]);
    assert_eq!(item.modified_at, 5_000);

    // Nothing to clear: no restamp.
    v.clear_history(id, 9_000).unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, 5_000);
    assert!(matches!(
        v.clear_history(Uuid::nil(), 9_000),
        Err(VaultError::Malformed(_))
    ));

    // Cap: stamps from earlier removals plus a full history keep only the 10 newest.
    let (mut v, id) = vault_with_history(HISTORY_CAP as u64);
    v.update(id, 3_000, |item| {
        item.removed_history = vec![10, 20, 30];
    })
    .unwrap();
    v.clear_history(id, 5_000).unwrap();
    let want: Vec<u64> = (1..=HISTORY_CAP as u64).rev().map(|i| 2_000 + i).collect();
    assert_eq!(v.get(id).unwrap().removed_history, want);
}

#[test]
fn removed_history_is_capped_newest_first_and_purged() {
    let (mut v, id) = vault_with_history(1);
    // Feed stamps through `update` (normalised there too), then remove real entries on top.
    v.update(id, 3_000, |item| {
        item.removed_history = (1..=12).rev().map(|i| i * 100).collect();
        item.removed_history.push(500); // duplicate
        item.removed_history.push(50); // out of order
    })
    .unwrap();
    let got = &v.get(id).unwrap().removed_history;
    assert_eq!(got.len(), HISTORY_CAP);
    assert_eq!(got[0], 1_200);
    assert_eq!(got[9], 300, "oldest fell off, duplicates collapsed");
    assert!(got.windows(2).all(|w| w[0] > w[1]));

    v.remove_history_entry(id, 2_001, 4_000).unwrap();
    let got = &v.get(id).unwrap().removed_history;
    assert_eq!(got.len(), HISTORY_CAP);
    assert_eq!(got[0], 2_001);
    assert_eq!(got[9], 400);

    // Purge drops stamps strictly older than the cutoff; items are not restamped.
    let before = v.get(id).unwrap().modified_at;
    assert_eq!(v.purge_tombstones_older_than(1_000), 0);
    assert_eq!(
        v.get(id).unwrap().removed_history,
        vec![2_001, 1_200, 1_100, 1_000]
    );
    assert_eq!(v.get(id).unwrap().modified_at, before);
    v.purge_tombstones_older_than(u64::MAX);
    assert!(v.get(id).unwrap().removed_history.is_empty());

    // `insert` normalises as well.
    let mut item = sample_item(2, 1);
    item.removed_history = vec![1, 3, 2, 3];
    let id2 = v.insert(item, 1);
    assert_eq!(v.get(id2).unwrap().removed_history, vec![3, 2, 1]);
}

#[test]
fn removed_history_cbor_shape_and_absent_when_empty() {
    let (mut v, id) = vault_with_history(2);
    let entries = plain_map(&v, id);
    assert!(
        key(&entries, "removed_history").is_none(),
        "optional key absent when empty: v1 bytes unchanged"
    );

    v.remove_history_entry(id, 2_001, 3_000).unwrap();
    v.remove_history_entry(id, 2_002, 3_001).unwrap();
    let entries = plain_map(&v, id);
    assert_eq!(
        key(&entries, "removed_history"),
        Some(Value::Array(vec![
            Value::Integer(2_002.into()),
            Value::Integer(2_001.into())
        ])),
        "exact shape: [u64] newest first"
    );
    let keys: Vec<String> = entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.clone(),
            _ => panic!("text keys"),
        })
        .collect();
    assert_eq!(
        keys,
        [
            "tags",
            "title",
            "fields",
            "history",
            "favorite",
            "device_id",
            "created_at",
            "deleted_at",
            "attachments",
            "removed_history"
        ],
        "canonical key order"
    );

    // Full round trip through the file.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    assert!(item_eq(v.get(id).unwrap(), u.get(id).unwrap()));
    assert_eq!(u.get(id).unwrap().removed_history, vec![2_002, 2_001]);

    // Null and missing read as empty; a non-integer entry is Malformed.
    let item = v.get(id).unwrap();
    let reencode = |edit: &dyn Fn(&mut Entries)| {
        let mut entries = plain_map(&v, id);
        edit(&mut entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
        format::decode_item_plain(&buf, item.id, item.modified_at)
    };
    let null = reencode(&|e| {
        for (k, val) in e.iter_mut() {
            if k == &Value::Text("removed_history".into()) {
                *val = Value::Null;
            }
        }
    })
    .unwrap();
    assert!(null.removed_history.is_empty());
    let missing =
        reencode(&|e| e.retain(|(k, _)| k != &Value::Text("removed_history".into()))).unwrap();
    assert!(missing.removed_history.is_empty());
    assert_eq!(missing.history.len(), 0, "history itself is unaffected");
    let bad = reencode(&|e| {
        for (k, val) in e.iter_mut() {
            if k == &Value::Text("removed_history".into()) {
                *val = Value::Array(vec![Value::Text("x".into())]);
            }
        }
    });
    assert!(matches!(bad, Err(VaultError::Malformed(_))));
}

#[test]
fn removed_entry_stays_removed_after_merge_both_ways() {
    let (v, id) = vault_with_history(3);
    let (mut a, mut b) = two_copies(&v);
    a.remove_history_entry(id, 2_002, 5_000).unwrap();
    // B keeps editing the item so it is the metadata winner on both sides, and B still
    // holds the entry A removed.
    b.update(id, 6_000, |item| item.title = "B edit".into())
        .unwrap();
    assert_eq!(stamps(&b, id), vec![2_003, 2_002, 2_001]);

    let ra = a.merge_from(&b).unwrap();
    assert_eq!(ra.updated, 1);
    assert_eq!(a.get(id).unwrap().title, "B edit");
    assert_eq!(stamps(&a, id), vec![2_003, 2_001], "a: still removed");
    assert_eq!(a.get(id).unwrap().removed_history, vec![2_002]);

    let rb = b.merge_from(&a).unwrap();
    assert_eq!(rb.updated, 1);
    assert_eq!(stamps(&b, id), vec![2_003, 2_001], "b: removal applied");
    assert_eq!(b.get(id).unwrap().removed_history, vec![2_002]);

    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    assert!(item_eq(a.get(id).unwrap(), b.get(id).unwrap()));
    assert!(!a.merge_from(&b).unwrap().changed());
    assert!(!b.merge_from(&a).unwrap().changed());

    // Both sides removed different entries: the union applies both.
    let (mut a, mut b) = two_copies(&v);
    a.remove_history_entry(id, 2_001, 5_000).unwrap();
    b.remove_history_entry(id, 2_003, 5_000).unwrap();
    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    assert_eq!(stamps(&a, id), vec![2_002]);
    assert_eq!(stamps(&b, id), vec![2_002]);
    assert_eq!(a.get(id).unwrap().removed_history, vec![2_003, 2_001]);
    assert!(item_eq(a.get(id).unwrap(), b.get(id).unwrap()));

    // A conflict loser whose stamp was removed is dropped too: B's password change at 2_002
    // loses to A's at 2_010, but A removed stamp 2_002 so the loser never lands.
    let (mut a, mut b) = two_copies(&v);
    a.remove_history_entry(id, 2_002, 5_000).unwrap();
    a.set_field(id, "password", secret("a-new"), 2_010).unwrap();
    b.update(id, 2_002, |item| {
        let f = item
            .fields
            .iter_mut()
            .find(|f| f.name == "password")
            .unwrap();
        f.value = secret("b-loser");
        f.modified_at = 2_002;
    })
    .unwrap();
    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    let values: Vec<&str> = a
        .get(id)
        .unwrap()
        .history
        .iter()
        .map(|h| h.value.expose_secret().as_str())
        .collect();
    assert!(!values.contains(&"b-loser"), "{values:?}");
    assert!(!values.contains(&"pw-1"), "{values:?}");
    assert!(item_eq(a.get(id).unwrap(), b.get(id).unwrap()));

    // Item tombstone cases clone wholesale: a tombstone keeps its history as-is.
    let (mut a, mut b) = two_copies(&v);
    a.delete(id, 6_000).unwrap();
    b.remove_history_entry(id, 2_002, 5_000).unwrap();
    a.merge_from(&b).unwrap();
    assert!(a.get(id).unwrap().is_deleted());
    assert_eq!(stamps(&a, id), vec![2_003, 2_002, 2_001]);
    assert!(a.get(id).unwrap().removed_history.is_empty());
    b.merge_from(&a).unwrap();
    assert!(item_eq(a.get(id).unwrap(), b.get(id).unwrap()));
}

#[test]
fn set_field_never_reuses_a_removed_stamp() {
    // Normal flow: every stamp a later set_field produces is past every removed stamp.
    let (v, id) = vault_with_history(3);
    let (mut a, mut b) = two_copies(&v);
    a.remove_history_entry(id, 2_003, 5_000).unwrap();
    b.set_field(id, "password", secret("b1"), 2_500).unwrap();
    a.merge_from(&b).unwrap();
    b.merge_from(&a).unwrap();
    for (v, now) in [(&mut a, 100u64), (&mut b, 100)] {
        v.set_field(id, "password", secret("again"), now).unwrap();
        let item = v.get(id).unwrap();
        let newest = item.history[0].replaced_at;
        assert_eq!(newest, item.field("password").unwrap().modified_at);
        assert!(
            !item.removed_history.contains(&newest),
            "{newest} in {:?}",
            item.removed_history
        );
        assert!(item.removed_history.iter().all(|s| *s < newest));
    }

    // Crafted: the field's timestamp moved back by hand through `update` so the next stamp
    // would collide with a removed one; it is bumped past it instead.
    let (mut v, id) = vault_with_history(2);
    v.remove_history_entry(id, 2_002, 3_000).unwrap();
    v.update(id, 3_001, |item| {
        let f = item
            .fields
            .iter_mut()
            .find(|f| f.name == "password")
            .unwrap();
        f.modified_at = 2_001;
    })
    .unwrap();
    assert_eq!(
        v.get(id).unwrap().field("password").unwrap().modified_at,
        2_001
    );
    v.set_field(id, "password", secret("x"), 100).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(item.history[0].replaced_at, 2_003, "2_002 skipped");
    assert_eq!(item.field("password").unwrap().modified_at, 2_003);
    assert_eq!(item.removed_history, vec![2_002]);
    assert_eq!(item.history[0].value.expose_secret(), "pw-2");
    // Round trip and a self-merge leave it in place.
    let u = unlock(&v.serialize()).unwrap();
    assert!(!v.merge_from(&u).unwrap().changed());
    assert_eq!(stamps(&v, id), vec![2_003, 2_001]);
}
