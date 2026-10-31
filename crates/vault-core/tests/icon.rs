//! `ItemPlain.icon` (01 §4, v1.2): optional per-item icon choice, stored by core and
//! interpreted by the app. Round trip of every shape, absent-key behaviour, unknown-key
//! preservation inside the icon map, malformed values, merge semantics, and the promise
//! that pre-icon fixtures are unaffected.

mod common;

use ciborium::Value;
use common::*;
use vault_core::format::{self, VaultFile};
use vault_core::vault::merge::item_eq;
use vault_core::{Item, ItemIcon, Uuid, VaultError};

type Entries = Vec<(Value, Value)>;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn symbol() -> ItemIcon {
    ItemIcon {
        kind: "symbol".into(),
        value: "key.fill".into(),
        color: Some("#3B82F6".into()),
        extras: Vec::new(),
    }
}

fn logo() -> ItemIcon {
    ItemIcon::new("logo", "github.com")
}

/// The decoded `ItemPlain` map of one item.
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

/// Re-encode an item's plaintext after editing the map, then decode it again.
fn reencode(item: &Item, edit: impl FnOnce(&mut Entries)) -> Result<Item, VaultError> {
    let mut entries = plain_map(item);
    edit(&mut entries);
    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
    format::decode_item_plain(&buf, item.id, item.modified_at)
}

fn set_icon(entries: &mut Entries, v: Value) {
    match entries.iter_mut().find(|(k, _)| k == &t("icon")) {
        Some((_, slot)) => *slot = v,
        None => entries.push((t("icon"), v)),
    }
}

#[test]
fn three_shapes_round_trip_through_a_file() {
    let mut v = new_vault();
    let mut with_symbol = sample_item(0, 10);
    with_symbol.icon = Some(symbol());
    let mut with_logo = sample_item(1, 10);
    with_logo.icon = Some(logo());
    let without = sample_item(2, 10);
    assert_eq!(without.icon, None, "Item::new starts without an icon");
    let a = v.insert(with_symbol, 10);
    let b = v.insert(with_logo, 10);
    let c = v.insert(without, 10);

    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    assert_eq!(u.get(a).unwrap().icon, Some(symbol()));
    assert_eq!(u.get(b).unwrap().icon, Some(logo()));
    assert_eq!(u.get(c).unwrap().icon, None);
    for id in [a, b, c] {
        assert!(item_eq(v.get(id).unwrap(), u.get(id).unwrap()));
    }

    // Exact CBOR shape: a map with text kind/value, colour only when Some.
    let entries = plain_map(u.get(a).unwrap());
    assert_eq!(
        key(&entries, "icon"),
        Some(Value::Map(vec![
            (t("kind"), t("symbol")),
            (t("color"), t("#3B82F6")),
            (t("value"), t("key.fill")),
        ])),
        "canonical order inside the icon map: kind, color, value"
    );
    let entries = plain_map(u.get(b).unwrap());
    assert_eq!(
        key(&entries, "icon"),
        Some(Value::Map(vec![
            (t("kind"), t("logo")),
            (t("value"), t("github.com"))
        ])),
        "no color key when None"
    );
}

#[test]
fn absent_icon_reads_as_none_and_emits_no_key() {
    let item = sample_item(3, 10);
    let entries = plain_map(&item);
    assert!(
        key(&entries, "icon").is_none(),
        "no icon, no key: v1 bytes unchanged"
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
            "deleted_at",
            "attachments"
        ],
        "key set of an icon-less item is exactly the v1 set"
    );

    // Missing and null both decode as None.
    let missing = reencode(&item, |e| e.retain(|(k, _)| k != &t("icon"))).unwrap();
    assert_eq!(missing.icon, None);
    let null = reencode(&item, |e| set_icon(e, Value::Null)).unwrap();
    assert_eq!(null.icon, None);

    // With an icon the key sorts first (4-byte key, 'i' < 't').
    let mut item = item;
    item.icon = Some(logo());
    let entries = plain_map(&item);
    assert_eq!(entries[0].0, t("icon"));
}

#[test]
fn unknown_keys_inside_the_icon_map_survive_a_read_write_cycle() {
    let mut v = new_vault();
    let mut item = sample_item(4, 10);
    let mut icon = symbol();
    icon.extras
        .push((t("x_icon_future"), Value::Integer(7.into())));
    icon.extras
        .push((t("x_nested"), Value::Map(vec![(t("a"), Value::Bool(true))])));
    // A colliding extra is dropped, never duplicated, exactly like item-level extras.
    icon.extras.push((t("kind"), t("shadow")));
    item.icon = Some(icon);
    let id = v.insert(item, 10);

    let u = unlock(&v.serialize()).unwrap();
    let got = u.get(id).unwrap().icon.as_ref().unwrap();
    assert_eq!(
        got.kind, "symbol",
        "a colliding extra never shadows the real key"
    );
    assert_eq!(got.value, "key.fill");
    assert_eq!(got.color.as_deref(), Some("#3B82F6"));
    assert_eq!(
        got.extras,
        vec![
            (t("x_nested"), Value::Map(vec![(t("a"), Value::Bool(true))])),
            (t("x_icon_future"), Value::Integer(7.into())),
        ],
        "unknown keys kept in canonical order, colliding one dropped"
    );

    // Second cycle is stable and the map has exactly one `kind`.
    let u2 = unlock(&u.serialize()).unwrap();
    assert_vaults_eq(&u, &u2);
    let Some(Value::Map(m)) = key(&plain_map(u2.get(id).unwrap()), "icon") else {
        panic!("icon is a map")
    };
    assert_eq!(m.iter().filter(|(k, _)| k == &t("kind")).count(), 1);
    assert!(m.iter().any(|(k, _)| k == &t("x_icon_future")));
}

#[test]
fn malformed_icon_values_are_rejected() {
    let mut item = sample_item(5, 10);
    item.icon = Some(symbol());
    let bad = |v: Value| reencode(&item, |e| set_icon(e, v));
    let cases: Vec<(&str, Value)> = vec![
        ("text instead of map", t("symbol")),
        (
            "array instead of map",
            Value::Array(vec![t("symbol"), t("key.fill")]),
        ),
        ("integer", Value::Integer(1.into())),
        ("empty map (missing kind and value)", Value::Map(vec![])),
        ("missing value", Value::Map(vec![(t("kind"), t("symbol"))])),
        (
            "missing kind",
            Value::Map(vec![(t("value"), t("key.fill"))]),
        ),
        (
            "kind not text",
            Value::Map(vec![
                (t("kind"), Value::Integer(1.into())),
                (t("value"), t("x")),
            ]),
        ),
        (
            "value not text",
            Value::Map(vec![
                (t("kind"), t("symbol")),
                (t("value"), Value::Bytes(vec![1])),
            ]),
        ),
        (
            "color not text",
            Value::Map(vec![
                (t("kind"), t("symbol")),
                (t("value"), t("x")),
                (t("color"), Value::Integer(0xff.into())),
            ]),
        ),
        (
            "duplicate key",
            Value::Map(vec![
                (t("kind"), t("symbol")),
                (t("kind"), t("logo")),
                (t("value"), t("x")),
            ]),
        ),
    ];
    for (what, v) in cases {
        assert!(
            matches!(bad(v), Err(VaultError::Malformed(_))),
            "{what}: must be Malformed"
        );
    }
    // Null colour is tolerated (same as a missing one).
    let ok = bad(Value::Map(vec![
        (t("kind"), t("symbol")),
        (t("value"), t("x")),
        (t("color"), Value::Null),
    ]))
    .unwrap();
    assert_eq!(ok.icon, Some(ItemIcon::new("symbol", "x")));

    // Through the whole file: a malformed icon fails unlock as Malformed, like a bad
    // attachments entry does. The writer emits an `icon` *extra* verbatim when the item
    // itself has `icon = None` (the key is only reserved while `Some`, the same rule as the
    // other optional keys), which is the one way this build can write an invalid icon.
    let mut v = new_vault();
    let id = v.insert(sample_item(6, 10), 10);
    v.update(id, 11, |i| i.extras.push((t("icon"), t("nope"))))
        .unwrap();
    let err = unlock(&v.serialize()).err().unwrap();
    assert!(matches!(err, VaultError::Malformed(_)), "got {err:?}");
}

#[test]
fn merge_keeps_the_winners_icon_and_a_differing_icon_is_a_change() {
    // item_eq: only the icon differs.
    let a = sample_item(7, 10);
    let mut b = a.clone();
    assert!(item_eq(&a, &b));
    b.icon = Some(logo());
    assert!(!item_eq(&a, &b), "None vs Some is a difference");
    let mut c = b.clone();
    c.icon = Some(symbol());
    assert!(!item_eq(&b, &c), "two different icons differ");
    c.icon = Some(logo());
    assert!(item_eq(&b, &c));

    // Two devices; the metadata winner's icon travels, including "winner has none".
    let mut a = new_vault();
    a.set_device_id(Uuid::from_u128(0xAAAA));
    let id = a.insert(sample_item(8, 1_000), 1_000);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(Uuid::from_u128(0xBBBB));

    // A sets a symbol at 5_000, B sets a logo at 6_000: B is newer and wins.
    a.update(id, 5_000, |i| i.icon = Some(symbol())).unwrap();
    b.update(id, 6_000, |i| i.icon = Some(logo())).unwrap();
    let ra = a.merge_from(&b).unwrap();
    assert_eq!(ra.updated, 1, "a differing icon alone counts as a change");
    assert_eq!(a.get(id).unwrap().icon, Some(logo()));
    let rb = b.merge_from(&a).unwrap();
    assert_eq!(rb.updated, 0, "B already held the winner");
    assert_vaults_eq(&a, &b);

    // The winner clearing the icon wins over the loser keeping one.
    b.update(id, 7_000, |i| i.icon = None).unwrap();
    let ra = a.merge_from(&b).unwrap();
    assert_eq!(ra.updated, 1);
    assert_eq!(a.get(id).unwrap().icon, None);

    // A merge that changes nothing but has equal icons reports no update.
    let r = a.merge_from(&b).unwrap();
    assert_eq!((r.updated, r.added), (0, 0));

    // `update` notices an icon-only change: the item is restamped.
    let before = a.get(id).unwrap().modified_at;
    a.update(id, 8_000, |i| i.icon = Some(symbol())).unwrap();
    assert!(a.get(id).unwrap().modified_at > before);
    assert_eq!(a.get(id).unwrap().modified_at, 8_000);
}

#[test]
fn pre_icon_fixtures_still_parse_unchanged_with_no_icon() {
    const BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
    const STAMPED: &[u8] = include_bytes!("fixtures/v1-stamped.vault");
    for (name, bytes) in [("v1-basic", BASIC), ("v1-stamped", STAMPED)] {
        let file = VaultFile::parse(bytes).unwrap();
        assert_eq!(file.to_bytes(), bytes, "{name}: structural round trip");
        let v = unlock(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(v.items_including_deleted().count() > 0, "{name}: has items");
        for item in v.items_including_deleted() {
            assert_eq!(item.icon, None, "{name}: {} has no icon", item.title);
            assert!(
                key(&plain_map(item), "icon").is_none(),
                "{name}: re-encoding never invents an icon key"
            );
        }
        let again = unlock(&v.serialize()).unwrap();
        assert_vaults_eq(&v, &again);
    }
}
