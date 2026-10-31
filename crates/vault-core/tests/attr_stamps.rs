//! Per-attribute stamps for `title`, `favorite`, `tags` and `icon` (PA-1, 2026-10-31; 01 §4
//! next to `created_at`, 03 §5 "both live" row): on-disk shape, `update` stamping, `insert`
//! filling, and the per-attribute merge so concurrent edits of different attributes on two
//! devices both survive, in one round and in both orders.

mod common;

use ciborium::Value;
use common::*;
use vault_core::format;
use vault_core::vault::merge::{item_eq, merge_items};
use vault_core::{ExposeSecret, FORMAT_VERSION, Item, ItemIcon, UnlockedVault, Uuid, VaultError};

type Entries = Vec<(Value, Value)>;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn dev_a() -> Uuid {
    Uuid::from_u128(0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA)
}

fn dev_b() -> Uuid {
    Uuid::from_u128(0xBBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB)
}

fn two_devices() -> (UnlockedVault, UnlockedVault, Uuid) {
    let mut a = new_vault();
    a.set_device_id(dev_a());
    // sample_item(1): favorite is false, so "set favorite = true" is a real change.
    let id = a.insert(sample_item(1, 1_000), 1_000);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    (a, b, id)
}

/// One merge round from snapshots, both directions.
fn one_round(a: &mut UnlockedVault, b: &mut UnlockedVault) {
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
}

/// Two rounds, then convergence and idempotence.
fn converge(a: &mut UnlockedVault, b: &mut UnlockedVault) {
    one_round(a, b);
    one_round(a, b);
    assert_vaults_eq(a, b);
    let b_snap = unlock(&b.serialize()).unwrap();
    assert!(!a.merge_from(&b_snap).unwrap().changed());
}

fn plain_map(item: &Item) -> Entries {
    let plain = format::encode_item_plain(item);
    let v: Value = ciborium::from_reader(plain.as_slice()).unwrap();
    assert!(format::is_canonical(&v));
    let Value::Map(entries) = v else {
        panic!("ItemPlain is a map")
    };
    entries
}

fn key(entries: &Entries, k: &str) -> Option<Value> {
    entries
        .iter()
        .find(|(kk, _)| kk == &t(k))
        .map(|(_, v)| v.clone())
}

fn reencode(item: &Item, edit: impl FnOnce(&mut Entries)) -> Result<Item, VaultError> {
    let mut entries = plain_map(item);
    edit(&mut entries);
    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
    format::decode_item_plain(&buf, item.id, item.modified_at, FORMAT_VERSION)
}

fn set_key(entries: &mut Entries, k: &str, v: Value) {
    match entries.iter_mut().find(|(kk, _)| kk == &t(k)) {
        Some((_, slot)) => *slot = v,
        None => entries.push((t(k), v)),
    }
}

const KEYS: [&str; 4] = [
    "title_modified_at",
    "favorite_modified_at",
    "tags_modified_at",
    "icon_modified_at",
];

fn stamps(i: &Item) -> [Option<u64>; 4] {
    [
        i.title_modified_at,
        i.favorite_modified_at,
        i.tags_modified_at,
        i.icon_modified_at,
    ]
}

// -------------------------------------------------------------------------------------------
// shape
// -------------------------------------------------------------------------------------------

#[test]
fn stamps_are_optional_keys_written_only_when_some() {
    // A caller-built item has none and writes none (pre-stamp bytes unchanged).
    let item = sample_item(1, 10);
    assert_eq!(stamps(&item), [None; 4]);
    let entries = plain_map(&item);
    for k in KEYS {
        assert!(key(&entries, k).is_none(), "{k}: absent when None");
    }

    // insert fills all four with the item stamp; they are written as u64.
    let mut v = new_vault();
    let id = v.insert(sample_item(1, 10), 10);
    let got = v.get(id).unwrap();
    assert_eq!(stamps(got), [Some(10); 4]);
    let entries = plain_map(got);
    for k in KEYS {
        assert_eq!(key(&entries, k), Some(Value::Integer(10.into())), "{k}");
    }
    let names: Vec<String> = entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.clone(),
            _ => panic!(),
        })
        .collect();
    let pos = |k: &str| names.iter().position(|n| n == k).unwrap();
    assert!(pos("attachments") < pos("icon_modified_at"));
    assert!(pos("icon_modified_at") < pos("tags_modified_at"));
    assert!(pos("tags_modified_at") < pos("title_modified_at"));
    assert!(pos("title_modified_at") < pos("favorite_modified_at"));

    // Round trip keeps them; null / missing read as None; a non-integer is Malformed.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    for k in KEYS {
        let null = reencode(got, |e| set_key(e, k, Value::Null)).unwrap();
        let missing = reencode(got, |e| e.retain(|(kk, _)| kk != &t(k))).unwrap();
        for i in [&null, &missing] {
            let s = stamps(i);
            assert_eq!(s.iter().filter(|x| x.is_none()).count(), 1, "{k}");
            assert_eq!(s.iter().filter(|x| **x == Some(10)).count(), 3, "{k}");
        }
        for bad in [t("x"), Value::Bytes(vec![1]), Value::Integer((-1).into())] {
            let r = reencode(got, |e| set_key(e, k, bad.clone()));
            assert!(matches!(r, Err(VaultError::Malformed(_))), "{k}");
        }
    }

    // Explicit stamps on a caller-built item are kept by insert (restamp covers them).
    let mut item = sample_item(2, 10);
    item.title_modified_at = Some(7);
    item.icon_modified_at = Some(50);
    let id = v.insert(item, 10);
    let got = v.get(id).unwrap();
    assert_eq!(got.title_modified_at, Some(7));
    assert_eq!(got.icon_modified_at, Some(50));
    assert_eq!(
        got.modified_at, 50,
        "item stamp covers the attribute stamps"
    );
    assert_eq!(
        got.favorite_modified_at,
        Some(50),
        "None filled with the item stamp"
    );
}

// -------------------------------------------------------------------------------------------
// update
// -------------------------------------------------------------------------------------------

#[test]
fn update_stamps_only_the_changed_attributes_monotonically() {
    let mut v = new_vault();
    let id = v.insert(sample_item(3, 1_000), 1_000);
    v.update(id, 2_000, |i| i.title = "renamed".into()).unwrap();
    let got = v.get(id).unwrap();
    assert_eq!(got.title_modified_at, Some(2_000));
    assert_eq!(got.favorite_modified_at, Some(1_000), "untouched");
    assert_eq!(got.tags_modified_at, Some(1_000));
    assert_eq!(got.icon_modified_at, Some(1_000));
    assert_eq!(got.modified_at, 2_000);

    // Clock behind: strictly advances from the attribute's previous stamp.
    v.update(id, 500, |i| i.favorite = !i.favorite).unwrap();
    assert_eq!(v.get(id).unwrap().favorite_modified_at, Some(1_001));
    assert_eq!(
        v.get(id).unwrap().modified_at,
        2_001,
        "item floor is stamp(now, prev item)"
    );

    // Tags are one set: any change stamps it; order change counts.
    v.update(id, 3_000, |i| i.tags.reverse()).unwrap();
    assert_eq!(v.get(id).unwrap().tags_modified_at, Some(3_000));
    v.update(id, 4_000, |i| i.icon = Some(ItemIcon::new("logo", "x.y")))
        .unwrap();
    assert_eq!(v.get(id).unwrap().icon_modified_at, Some(4_000));

    // An explicit stamp set by `f` on a changed attribute is respected (and lifts the item).
    v.update(id, 4_500, |i| {
        i.title = "again".into();
        i.title_modified_at = Some(9_000);
    })
    .unwrap();
    assert_eq!(v.get(id).unwrap().title_modified_at, Some(9_000));
    assert_eq!(v.get(id).unwrap().modified_at, 9_000);

    // A metadata-only edit that changes no attribute leaves every stamp alone.
    v.update(id, 9_500, |i| i.created_at = Some(1)).unwrap();
    assert_eq!(v.get(id).unwrap().title_modified_at, Some(9_000));
    assert_eq!(v.get(id).unwrap().favorite_modified_at, Some(1_001));
    assert_eq!(v.get(id).unwrap().modified_at, 9_500);

    // A legacy item (no stamps) gets a stamp only for the attribute that changed.
    v.update(id, 9_600, |i| {
        i.title_modified_at = None;
        i.favorite_modified_at = None;
        i.tags_modified_at = None;
        i.icon_modified_at = None;
    })
    .unwrap();
    assert_eq!(stamps(v.get(id).unwrap()), [None; 4]);
    v.update(id, 9_700, |i| i.favorite = !i.favorite).unwrap();
    let got = v.get(id).unwrap();
    assert_eq!(
        got.favorite_modified_at,
        Some(9_700),
        "stamp(now, effective 9_600)"
    );
    assert_eq!(
        stamps(got),
        [Some(9_600), Some(9_700), Some(9_600), Some(9_600)],
        "the untouched legacy stamps are pinned at the stamp they implicitly had"
    );

    // Every other mutation pins a legacy item's stamps too, so a later field edit cannot
    // make its untouched attributes look freshly edited.
    let mut v = new_vault();
    let id = v.insert(sample_item(5, 1_000), 1_000);
    v.update(id, 1_500, |i| {
        i.title_modified_at = None;
        i.favorite_modified_at = None;
        i.tags_modified_at = None;
        i.icon_modified_at = None;
    })
    .unwrap();
    assert_eq!(
        stamps(v.get(id).unwrap()),
        [None; 4],
        "explicit clear is kept"
    );
    v.set_field_named(id, "username", secret("x"), 2_000)
        .unwrap();
    assert_eq!(stamps(v.get(id).unwrap()), [Some(1_500); 4]);
    assert_eq!(v.get(id).unwrap().modified_at, 2_000);
}

// -------------------------------------------------------------------------------------------
// merge
// -------------------------------------------------------------------------------------------

#[test]
fn rename_on_a_and_favorite_on_b_both_survive_in_one_round_both_orders() {
    for a_first in [true, false] {
        let (mut a, mut b, id) = two_devices();
        a.update(id, 2_000, |i| i.title = "A's title".into())
            .unwrap();
        b.update(id, 3_000, |i| i.favorite = true).unwrap();
        if a_first {
            one_round(&mut a, &mut b);
        } else {
            one_round(&mut b, &mut a);
        }
        for v in [&a, &b] {
            let i = v.get(id).unwrap();
            assert_eq!(i.title, "A's title", "a_first={a_first}");
            assert!(i.favorite, "a_first={a_first}");
            assert_eq!(i.title_modified_at, Some(2_000));
            assert_eq!(i.favorite_modified_at, Some(3_000));
            assert_eq!(
                i.device_id,
                dev_b(),
                "item winner (3_000) supplies device_id"
            );
        }
        converge(&mut a, &mut b);
    }
}

#[test]
fn tags_on_a_and_icon_on_b_both_survive() {
    let (mut a, mut b, id) = two_devices();
    a.update(id, 2_500, |i| i.tags.push("from-a".into()))
        .unwrap();
    b.update(id, 2_000, |i| {
        i.icon = Some(ItemIcon::new("symbol", "key.fill"))
    })
    .unwrap();
    one_round(&mut a, &mut b);
    for v in [&a, &b] {
        let i = v.get(id).unwrap();
        assert!(i.tags.contains(&"from-a".to_owned()));
        assert_eq!(i.icon, Some(ItemIcon::new("symbol", "key.fill")));
        assert_eq!(i.tags_modified_at, Some(2_500));
        assert_eq!(i.icon_modified_at, Some(2_000));
        assert_eq!(i.device_id, dev_a());
    }
    converge(&mut a, &mut b);
}

#[test]
fn same_attribute_on_both_sides_later_wins_and_ties_are_symmetric() {
    let (mut a, mut b, id) = two_devices();
    a.update(id, 3_000, |i| i.title = "late A".into()).unwrap();
    b.update(id, 2_000, |i| i.title = "early B".into()).unwrap();
    b.update(id, 4_000, |i| i.favorite = true).unwrap();
    one_round(&mut a, &mut b);
    for v in [&a, &b] {
        let i = v.get(id).unwrap();
        assert_eq!(
            i.title, "late A",
            "later title wins even though B's item is newer"
        );
        assert!(i.favorite);
        assert_eq!(i.device_id, dev_b());
    }
    converge(&mut a, &mut b);

    // Equal stamps: greater device id wins; equal device id too: canonical bytes.
    let (mut a, mut b, id) = two_devices();
    a.update(id, 5_000, |i| i.title = "A".into()).unwrap();
    b.update(id, 5_000, |i| i.title = "B".into()).unwrap();
    one_round(&mut a, &mut b);
    assert_eq!(a.get(id).unwrap().title, "B");
    assert_eq!(b.get(id).unwrap().title, "B");
    let mut x = sample_item(4, 10);
    x.device_id = dev_a();
    let mut y = x.clone();
    x.title = "alpha".into();
    y.title = "omega".into();
    x.title_modified_at = Some(10);
    y.title_modified_at = Some(10);
    x.favorite = true;
    y.favorite = false;
    assert_eq!(merge_items(&x, &y).title, "omega");
    assert_eq!(merge_items(&y, &x).title, "omega");
    assert!(merge_items(&x, &y).favorite, "true > false in CBOR bytes");
    assert!(merge_items(&y, &x).favorite);
}

#[test]
fn legacy_items_merge_as_before_and_sensibly_against_stamped_ones() {
    // Two legacy copies (no stamps): metadata follows the item winner wholesale, no stamp
    // is invented, and an untouched copy is "unchanged".
    let clear = |i: &mut Item| {
        i.title_modified_at = None;
        i.favorite_modified_at = None;
        i.tags_modified_at = None;
        i.icon_modified_at = None;
    };
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(sample_item(1, 1_000), 1_000);
    a.update(id, 1_500, clear).unwrap();
    let a_snap = unlock(&a.serialize()).unwrap();
    assert_eq!(stamps(a_snap.get(id).unwrap()), [None; 4]);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    assert!(
        !b.merge_from(&a_snap).unwrap().changed(),
        "untouched legacy copy: unchanged"
    );
    assert_eq!(stamps(b.get(id).unwrap()), [None; 4]);
    assert!(item_eq(a.get(id).unwrap(), b.get(id).unwrap()));
    // A stamped copy merging a NEWER legacy copy materialises the legacy side's effective
    // stamp for every attribute it wins (so the later, larger item stamp cannot inflate it).
    let mut c = new_vault();
    c.set_device_id(dev_b());
    let mut fresh = a.get(id).unwrap().clone();
    fresh.id = id;
    let c_id = c.insert(fresh, 1_000);
    assert_eq!(c_id, id);
    let _ = c; // separate vault_id; only built to show insert fills stamps
    let (mut s_a, mut s_b, s_id) = two_devices();
    s_a.update(s_id, 1_500, clear).unwrap();
    let s_a_snap = unlock(&s_a.serialize()).unwrap();
    s_b.merge_from(&s_a_snap).unwrap();
    assert_eq!(stamps(s_b.get(s_id).unwrap()), [Some(1_500); 4]);
    // Legacy vs legacy, both edited (items as a pre-stamp writer left them: no stamps at
    // all, so built by hand and merged with the pure function; `update` would stamp a
    // changed attribute): the newer item wins every attribute wholesale, as before, and
    // no stamp is invented. Symmetric in both orders.
    let mut x = a.get(id).unwrap().clone();
    let mut y = x.clone();
    x.title = "A".into();
    x.modified_at = 2_000;
    x.device_id = dev_a();
    y.favorite = true;
    y.modified_at = 3_000;
    y.device_id = dev_b();
    for m in [merge_items(&x, &y), merge_items(&y, &x)] {
        assert_eq!(
            m.title, "Item 1 \u{1F511} caf\u{e9}",
            "B's whole metadata, title included"
        );
        assert!(m.favorite);
        assert_eq!(stamps(&m), [None; 4], "no stamp invented");
        assert_eq!(m.device_id, dev_b());
        assert_eq!(m.modified_at, 3_000);
    }
    // ... and `update` on a legacy item stamps the attribute it changed and pins the rest.
    a.update(id, 2_000, |i| i.title = "A".into()).unwrap();
    assert_eq!(
        stamps(a.get(id).unwrap()),
        [Some(2_000), Some(1_500), Some(1_500), Some(1_500)]
    );

    // Legacy (A, no stamps) vs stamped (B): A's item stamp is its effective stamp for every
    // attribute; B's older favorite edit loses to A's newer item, B's newer title edit wins.
    let (mut a, mut b, id) = two_devices();
    b.update(id, 2_000, |i| i.favorite = true).unwrap();
    b.update(id, 4_000, |i| i.title = "B title".into()).unwrap();
    a.update(id, 3_000, |i| {
        i.tags.push("a-tag".into());
        clear(i);
    })
    .unwrap();
    one_round(&mut a, &mut b);
    for v in [&a, &b] {
        let i = v.get(id).unwrap();
        assert_eq!(i.title, "B title", "4_000 > A's effective 3_000");
        assert!(!i.favorite, "A's effective 3_000 > B's 2_000");
        assert!(i.tags.contains(&"a-tag".to_owned()));
        assert_eq!(i.title_modified_at, Some(4_000));
        assert_eq!(
            i.favorite_modified_at,
            Some(3_000),
            "winner had no stamp, loser had: materialised at the effective stamp"
        );
        assert_eq!(i.tags_modified_at, Some(3_000));
    }
    converge(&mut a, &mut b);
}

#[test]
fn merge_laws_hold_with_attribute_stamps() {
    // Content change at an equal item stamp still bumps; idempotence and commutativity over
    // a mixed script.
    let (mut a, mut b, id) = two_devices();
    a.update(id, 2_000, |i| i.title = "A".into()).unwrap();
    b.update(id, 2_000, |i| i.favorite = true).unwrap();
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    let r = a.merge_from(&b_snap).unwrap();
    assert_eq!(r.updated, 1);
    assert_eq!(
        a.get(id).unwrap().modified_at,
        2_001,
        "bumped: content changed at equal max"
    );
    assert!(a.get(id).unwrap().favorite);
    assert_eq!(a.get(id).unwrap().title, "A");
    b.merge_from(&a_snap).unwrap();
    assert_eq!(b.get(id).unwrap().title, "A");
    converge(&mut a, &mut b);
    let u = unlock(&a.serialize()).unwrap();
    assert_vaults_eq(&a, &u);
    assert_eq!(
        u.get(id).unwrap().fields[0].value.expose_secret(),
        "user1@example.com"
    );
}

/// The QA u06 shape on a legacy item (a version 1 file's item, no attribute stamps): B
/// renames, then A, never having merged B, marks favorite later. Both must survive: the
/// pinning in `restamp` keeps A's untouched title at the old item stamp.
#[test]
fn legacy_item_rename_on_b_then_later_favorite_on_a_both_survive() {
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(sample_item(1, 1_000), 1_000);
    a.update(id, 1_000, |i| {
        i.title_modified_at = None;
        i.favorite_modified_at = None;
        i.tags_modified_at = None;
        i.icon_modified_at = None;
    })
    .unwrap();
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    assert_eq!(stamps(b.get(id).unwrap()), [None; 4]);
    b.update(id, 5_000, |i| i.title = "edited on B".into())
        .unwrap();
    a.update(id, 6_000, |i| i.favorite = true).unwrap();
    // A merges B's save (the pre-write merge), then B merges A's.
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    let a_snap = unlock(&a.serialize()).unwrap();
    b.merge_from(&a_snap).unwrap();
    for v in [&a, &b] {
        let i = v.get(id).unwrap();
        assert_eq!(i.title, "edited on B");
        assert!(i.favorite);
        assert_eq!(i.title_modified_at, Some(5_000));
        assert_eq!(i.favorite_modified_at, Some(6_000));
        assert_eq!(
            i.tags_modified_at,
            Some(1_001),
            "pinned at the old item stamp"
        );
    }
    converge(&mut a, &mut b);
}
