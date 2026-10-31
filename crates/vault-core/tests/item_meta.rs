//! `ItemPlain.created_at` and `Field.kind = "section"` (01 §4, v1.3, no version bump).
//!
//! `created_at`: round trip, absent-key behaviour, malformed shapes, the merge minimum rule
//! and the promise that a differing `created_at` alone is never an update. `section`: the
//! on-disk string, value shapes, "not sensitive", skipped by export, ignored by search, no
//! history on `set_field`, merged by name and stamp. Plus: pre-v1.3 fixtures still parse
//! unchanged with `created_at == None`.

mod common;

use ciborium::Value;
use common::*;
use vault_core::format::{self, VaultFile};
use vault_core::search::{Query, search};
use vault_core::vault::merge::{item_eq, merge_items};
use vault_core::{
    ExposeSecret, FORMAT_VERSION, Field, FieldKind, Item, Uuid, VaultError, export_csv,
};

type Entries = Vec<(Value, Value)>;

fn t(s: &str) -> Value {
    Value::Text(s.into())
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
    format::decode_item_plain(&buf, item.id, item.modified_at, FORMAT_VERSION)
}

fn set_key(entries: &mut Entries, k: &str, v: Value) {
    match entries.iter_mut().find(|(kk, _)| kk == &t(k)) {
        Some((_, slot)) => *slot = v,
        None => entries.push((t(k), v)),
    }
}

fn section(name: &str, now: u64) -> Field {
    Field::new(name, FieldKind::Section, secret(""), now)
}

/// Edit the first field map of the item's plaintext.
fn edit_first_field(entries: &mut Entries, edit: impl FnOnce(&mut Entries)) {
    let Some((_, Value::Array(fields))) = entries.iter_mut().find(|(k, _)| k == &t("fields"))
    else {
        panic!("fields is an array")
    };
    let Some(Value::Map(first)) = fields.first_mut() else {
        panic!("at least one field map")
    };
    edit(first);
}

// -------------------------------------------------------------------------------------------
// created_at
// -------------------------------------------------------------------------------------------

#[test]
fn created_at_round_trips_through_a_file_and_is_set_by_item_new() {
    let mut v = new_vault();
    let dated = sample_item(0, 10);
    assert_eq!(
        dated.created_at,
        Some(10),
        "Item::new stamps created_at = now"
    );
    let mut undated = sample_item(1, 10);
    undated.created_at = None;
    let mut old = sample_item(2, 10);
    old.created_at = Some(3);
    let a = v.insert(dated, 10);
    let b = v.insert(undated, 10);
    let c = v.insert(old, 10);
    assert_eq!(v.get(a).unwrap().created_at, Some(10));
    assert_eq!(
        v.get(b).unwrap().created_at,
        None,
        "insert leaves None alone"
    );
    assert_eq!(
        v.get(c).unwrap().created_at,
        Some(3),
        "insert never rewrites created_at"
    );

    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    assert_eq!(u.get(a).unwrap().created_at, Some(10));
    assert_eq!(u.get(b).unwrap().created_at, None);
    assert_eq!(u.get(c).unwrap().created_at, Some(3));

    // Exact CBOR shape: an unsigned integer under `created_at`.
    let entries = plain_map(u.get(c).unwrap());
    assert_eq!(key(&entries, "created_at"), Some(Value::Integer(3.into())));
    // Canonical position: 10-byte key, sorts right before `deleted_at`.
    let keys: Vec<String> = entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.clone(),
            _ => panic!("text keys"),
        })
        .collect();
    let c_at = keys.iter().position(|k| k == "created_at").unwrap();
    assert_eq!(keys[c_at + 1], "deleted_at");
    assert_eq!(keys[c_at - 1], "device_id");
}

#[test]
fn absent_created_at_reads_as_none_and_emits_no_key() {
    let mut item = sample_item(3, 10);
    item.created_at = None;
    let entries = plain_map(&item);
    assert!(
        key(&entries, "created_at").is_none(),
        "None, no key: pre-v1.3 bytes unchanged"
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
        "key set of an item without created_at is exactly the v1 set"
    );

    // Missing and null both decode as None.
    let dated = sample_item(4, 10);
    assert_eq!(
        plain_map(&dated).len(),
        9,
        "fresh item: v1 set + created_at"
    );
    let missing = reencode(&dated, |e| e.retain(|(k, _)| k != &t("created_at"))).unwrap();
    assert_eq!(missing.created_at, None);
    let null = reencode(&dated, |e| set_key(e, "created_at", Value::Null)).unwrap();
    assert_eq!(null.created_at, None);
    // Zero is a value, not "unknown".
    let zero = reencode(&dated, |e| {
        set_key(e, "created_at", Value::Integer(0.into()))
    })
    .unwrap();
    assert_eq!(zero.created_at, Some(0));
}

#[test]
fn malformed_created_at_is_rejected() {
    let item = sample_item(5, 10);
    let bad = |v: Value| reencode(&item, |e| set_key(e, "created_at", v));
    let cases: Vec<(&str, Value)> = vec![
        ("text", t("1700000000000")),
        ("negative", Value::Integer((-1).into())),
        ("bool", Value::Bool(true)),
        ("float", Value::Float(1.0)),
        ("array", Value::Array(vec![Value::Integer(1.into())])),
        ("map", Value::Map(vec![(t("at"), Value::Integer(1.into()))])),
        ("bytes", Value::Bytes(vec![1, 2, 3])),
    ];
    for (what, v) in cases {
        assert!(
            matches!(bad(v), Err(VaultError::Malformed(_))),
            "{what}: must be Malformed"
        );
    }
    // The whole u64 range is a value.
    let max = bad(Value::Integer(u64::MAX.into())).unwrap();
    assert_eq!(max.created_at, Some(u64::MAX));

    // Through the whole file: a malformed created_at fails unlock as Malformed. The writer
    // emits a `created_at` *extra* verbatim while the item's own `created_at` is None (the
    // key is reserved only while `Some`, the same rule as `icon`).
    let mut v = new_vault();
    let id = v.insert(sample_item(6, 10), 10);
    v.update(id, 11, |i| {
        i.created_at = None;
        i.extras.push((t("created_at"), t("nope")));
    })
    .unwrap();
    let err = unlock(&v.serialize()).err().unwrap();
    assert!(matches!(err, VaultError::Malformed(_)), "got {err:?}");

    // And a colliding extra is dropped, never duplicated, when the item has a real value.
    let mut v = new_vault();
    let id = v.insert(sample_item(7, 10), 10);
    v.update(id, 11, |i| i.extras.push((t("created_at"), t("shadow"))))
        .unwrap();
    let u = unlock(&v.serialize()).unwrap();
    assert_eq!(u.get(id).unwrap().created_at, Some(10));
    assert!(u.get(id).unwrap().extras.is_empty());
}

#[test]
fn merge_keeps_the_minimum_created_at_and_never_counts_it_as_a_change() {
    // Pure rule, every combination.
    let a = sample_item(8, 10);
    let mut b = a.clone();
    let cases = [
        (Some(5), Some(9), Some(5)),
        (Some(9), Some(5), Some(5)),
        (Some(7), None, Some(7)),
        (None, Some(7), Some(7)),
        (None, None, None),
        (Some(4), Some(4), Some(4)),
    ];
    for (ours, theirs, want) in cases {
        let mut x = a.clone();
        x.created_at = ours;
        b.created_at = theirs;
        assert_eq!(
            merge_items(&x, &b).created_at,
            want,
            "{ours:?} vs {theirs:?}"
        );
        assert_eq!(merge_items(&b, &x).created_at, want, "commutative");
        assert_eq!(
            merge_items(&x, &b).modified_at,
            a.modified_at,
            "created_at never moves modified_at"
        );
    }
    // Tombstone outcomes carry the minimum too.
    let mut dead = a.clone();
    dead.deleted_at = Some(50);
    dead.modified_at = 50;
    dead.created_at = Some(9);
    let mut live = a.clone();
    live.created_at = Some(2);
    assert!(merge_items(&dead, &live).is_deleted());
    assert_eq!(merge_items(&dead, &live).created_at, Some(2));
    assert_eq!(merge_items(&live, &dead).created_at, Some(2));

    // `item_eq` ignores created_at: it is outside the "changed" decision.
    let mut c = a.clone();
    c.created_at = Some(1);
    assert!(
        item_eq(&a, &c),
        "differing created_at alone is not a change"
    );
    c.created_at = None;
    assert!(item_eq(&a, &c));

    // Two devices, same item, nothing but created_at differs: no update, no restamp, but
    // the minimum is carried into ours.
    let mut va = new_vault();
    va.set_device_id(Uuid::from_u128(0xAAAA));
    let mut item = sample_item(9, 1_000);
    item.created_at = Some(900);
    let id = va.insert(item, 1_000);
    // The peer's copy: identical content and stamp, older created_at (as if it had learnt
    // the earlier value from a third device). `update` would restamp, so the copy is
    // re-inserted into an emptied twin of A at the exact same stamp instead.
    let mut spliced = va.get(id).unwrap().clone();
    spliced.created_at = Some(100);
    let mut peer = emptied_twin(&va);
    // `insert` stamps `device_id = self.device_id`; a real peer's copy carries the id of
    // the device that made the last change (A), so insert under A's id, then become B.
    peer.set_device_id(Uuid::from_u128(0xAAAA));
    let stamp = spliced.modified_at;
    peer.insert(spliced, stamp);
    peer.set_device_id(Uuid::from_u128(0xBBBB));
    assert_eq!(
        peer.get(id).unwrap().modified_at,
        stamp,
        "no restamp on a fresh id"
    );
    assert_eq!(peer.get(id).unwrap().created_at, Some(100));
    assert!(
        item_eq(va.get(id).unwrap(), peer.get(id).unwrap()),
        "only created_at differs"
    );

    let before = va.get(id).unwrap().modified_at;
    let r = va.merge_from(&peer).unwrap();
    assert_eq!((r.added, r.updated, r.deleted), (0, 0, 0), "not an update");
    assert_eq!(r.unchanged, 1);
    assert!(
        !r.changed(),
        "a created_at-only difference does not ask for a save"
    );
    assert_eq!(va.get(id).unwrap().modified_at, before, "no restamp");
    assert_eq!(
        va.get(id).unwrap().created_at,
        Some(100),
        "but the minimum is carried"
    );
    // The other direction: the peer already holds the minimum, nothing moves.
    let r = peer.merge_from(&va).unwrap();
    assert_eq!(r.unchanged, 1);
    assert_eq!(peer.get(id).unwrap().created_at, Some(100));
    assert_eq!(peer.get(id).unwrap().modified_at, stamp);

    // A merge that *does* change content stamps as usual and still carries the minimum.
    peer.set_field_named(id, "username", secret("edited"), 5_000)
        .unwrap();
    let r = va.merge_from(&peer).unwrap();
    assert_eq!(r.updated, 1);
    assert_eq!(va.get(id).unwrap().created_at, Some(100));
    assert_eq!(va.get(id).unwrap().modified_at, 5_000);
}

/// A second, empty vault with the same `vault_id` and keys as `like` (so `merge_from`
/// accepts it): unlock `like`'s bytes, delete every item and purge the tombstones, so a
/// later `insert` of a known id has no floor and keeps the given stamp.
fn emptied_twin(like: &vault_core::UnlockedVault) -> vault_core::UnlockedVault {
    let mut v = unlock(&like.serialize()).unwrap();
    let ids: Vec<Uuid> = v.items_including_deleted().map(|i| i.id).collect();
    for id in ids {
        v.delete(id, 1).unwrap();
    }
    v.purge_tombstones_older_than(u64::MAX);
    assert_eq!(v.items_including_deleted().count(), 0);
    v
}

#[test]
fn update_may_change_created_at_and_restamps_like_any_edit() {
    let mut v = new_vault();
    let id = v.insert(sample_item(10, 1_000), 1_000);
    v.update(id, 2_000, |i| i.created_at = Some(500)).unwrap();
    assert_eq!(v.get(id).unwrap().created_at, Some(500));
    assert_eq!(
        v.get(id).unwrap().modified_at,
        2_000,
        "update restamps unconditionally"
    );
    v.update(id, 3_000, |i| i.created_at = None).unwrap();
    assert_eq!(v.get(id).unwrap().created_at, None);
    assert!(key(&plain_map(v.get(id).unwrap()), "created_at").is_none());
}

// -------------------------------------------------------------------------------------------
// section
// -------------------------------------------------------------------------------------------

#[test]
fn section_field_round_trips_as_the_string_section() {
    let mut v = new_vault();
    let mut item = sample_item(11, 10);
    item.fields.insert(0, section("Account", 10));
    // Core does not enforce an empty value: whatever is given is kept.
    let mut with_value = section("Loud heading", 10);
    with_value.value = secret("kept as given");
    item.fields.push(with_value);
    let id = v.insert(item, 10);

    let entries = plain_map(v.get(id).unwrap());
    let Some(Value::Array(fields)) = key(&entries, "fields") else {
        panic!("fields array")
    };
    let Value::Map(first) = &fields[0] else {
        panic!("field map")
    };
    assert!(
        first.contains(&(t("kind"), t("section"))),
        "on-disk kind string is exactly \"section\""
    );
    assert!(first.contains(&(t("value"), t(""))));

    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    let got = u.get(id).unwrap();
    assert_eq!(got.fields[0].kind, FieldKind::Section);
    assert_eq!(got.fields[0].name, "Account");
    assert_eq!(got.fields[0].kind_raw, None);
    assert_eq!(got.fields[0].kind_str(), "section");
    assert_eq!(got.fields[0].value.expose_secret(), "");
    // `Item::field` skips headings (a label lookup must not hit a heading named like a
    // value); the test helper finds any field by name.
    assert!(got.field("Loud heading").is_none());
    let loud = field_named(got, "Loud heading").unwrap();
    assert_eq!(loud.kind, FieldKind::Section);
    assert_eq!(loud.value.expose_secret(), "kept as given");
    assert!(item_eq(v.get(id).unwrap(), got));

    // The enum string is known: parse() recognises it and it is in ALL.
    assert_eq!(FieldKind::parse("section"), Some(FieldKind::Section));
    assert!(FieldKind::ALL.contains(&FieldKind::Section));
    assert_eq!(FieldKind::ALL.len(), 9);
}

#[test]
fn section_value_shapes_on_disk() {
    let mut item = sample_item(12, 10);
    item.fields.insert(0, section("Heading", 10));

    // Empty text: fine. Non-empty text: kept. Null / missing / non-text: Malformed, like
    // every other field value (the value key is required text regardless of kind).
    let ok = reencode(&item, |e| {
        edit_first_field(e, |f| set_key(f, "value", t("")))
    })
    .unwrap();
    assert_eq!(ok.fields[0].value.expose_secret(), "");
    let kept = reencode(&item, |e| {
        edit_first_field(e, |f| set_key(f, "value", t("non-empty")))
    })
    .unwrap();
    assert_eq!(kept.fields[0].value.expose_secret(), "non-empty");
    assert_eq!(kept.fields[0].kind, FieldKind::Section);
    for (what, v) in [
        ("null value", Value::Null),
        ("integer value", Value::Integer(1.into())),
        ("array value", Value::Array(vec![])),
        ("bytes value", Value::Bytes(vec![0])),
    ] {
        let r = reencode(&item, |e| edit_first_field(e, |f| set_key(f, "value", v)));
        assert!(
            matches!(r, Err(VaultError::Malformed(_))),
            "{what}: must be Malformed"
        );
    }
    let missing = reencode(&item, |e| {
        edit_first_field(e, |f| f.retain(|(k, _)| k != &t("value")))
    });
    assert!(matches!(missing, Err(VaultError::Malformed(_))));

    // The kind string itself must be text; an unknown spelling is `Other`, not `Section`.
    let other = reencode(&item, |e| {
        edit_first_field(e, |f| set_key(f, "kind", t("Section")))
    })
    .unwrap();
    assert_eq!(other.fields[0].kind, FieldKind::Other);
    assert_eq!(other.fields[0].kind_raw.as_deref(), Some("Section"));
    assert!(other.fields[0].kind.is_sensitive(), "unknown stays masked");
    let bad_kind = reencode(&item, |e| {
        edit_first_field(e, |f| set_key(f, "kind", Value::Integer(7.into())))
    });
    assert!(matches!(bad_kind, Err(VaultError::Malformed(_))));

    // A section may carry a `section` grouping label like any field; it is preserved.
    let labelled = reencode(&item, |e| {
        edit_first_field(e, |f| set_key(f, "section", t("group")))
    })
    .unwrap();
    assert_eq!(labelled.fields[0].section.as_deref(), Some("group"));
}

#[test]
fn section_is_not_sensitive_and_export_skips_it() {
    assert!(!FieldKind::Section.is_sensitive());
    assert!(
        !FieldKind::Section.is_other(),
        "a known kind, not a forward-compat placeholder"
    );

    let mut v = new_vault();
    let mut item = Item::new("Exported", device(), 1);
    // Headings whose names collide with export columns, one with a stray value.
    item.fields.push(section("Username", 1));
    let mut notes_heading = section("notes", 1);
    notes_heading.value = secret("not the notes");
    item.fields.push(notes_heading);
    item.fields.push(section("password", 1));
    item.fields.push(Field::new(
        "real notes",
        FieldKind::Notes,
        secret("the notes"),
        1,
    ));
    item.fields
        .push(Field::new("login", FieldKind::Email, secret("a@b.c"), 1));
    v.insert(item, 1);
    let out = export_csv(&v);
    let text = String::from_utf8(out.0.clone()).unwrap();
    assert!(
        text.contains("\nExported,a@b.c,,,the notes,\n"),
        "headings skipped by name and by kind; kind fallbacks still work: {text:?}"
    );
    assert!(!text.contains("not the notes"));
}

#[test]
fn search_ignores_section_fields() {
    let mut v = new_vault();
    let mut item = Item::new("Plain", device(), 1);
    item.fields.push(section("username", 1));
    let mut url_heading = section("Links", 1);
    url_heading.value = secret("https://zed.dev");
    item.fields.push(url_heading);
    let mut valued = section("Heading", 1);
    valued.value = secret("needle-in-value");
    item.fields.push(valued);
    item.fields.push(Field::new(
        "username",
        FieldKind::Text,
        secret("alice@example.com"),
        1,
    ));
    v.insert(item, 1);

    let q = |text: &str| {
        search(
            &v,
            &Query {
                text,
                tag: None,
                favorites_only: false,
            },
        )
        .len()
    };
    assert_eq!(q("needle"), 0, "a heading's value is never matched");
    assert_eq!(q("links"), 0, "a heading's name is never matched");
    assert_eq!(q("zed"), 0, "a heading never acts as a url field");
    assert_eq!(q("alice"), 1, "the real username still ranks");
    assert_eq!(q("plain"), 1);
}

#[test]
fn set_field_on_a_section_is_allowed_and_writes_no_history() {
    let mut v = new_vault();
    let mut item = Item::new("With heading", device(), 1_000);
    item.fields.push(section("Account", 1_000));
    item.fields.push(Field::new(
        "password",
        FieldKind::Password,
        secret("pw-1"),
        1_000,
    ));
    let id = v.insert(item, 1_000);
    let heading = v.get(id).unwrap().fields[0].id;

    // A heading is never addressed by name (`set_field_named` skips sections), only by id.
    assert_eq!(
        v.set_field_named(id, "Account", secret("x"), 2_000)
            .unwrap_err(),
        VaultError::FieldNotFound
    );
    v.set_field(id, heading, secret("renamed-value"), 2_000)
        .unwrap();
    let got = v.get(id).unwrap();
    assert_eq!(got.fields[0].value.expose_secret(), "renamed-value");
    assert_eq!(got.fields[0].modified_at, 2_000, "stamped like any field");
    assert_eq!(got.modified_at, 2_000);
    assert!(got.history.is_empty(), "no history for a heading");

    // The password field next to it still records history, so the guard is kind-based.
    v.set_field_named(id, "password", secret("pw-2"), 3_000)
        .unwrap();
    let got = v.get(id).unwrap();
    assert_eq!(got.history.len(), 1);
    assert_eq!(got.history[0].value.expose_secret(), "pw-1");
    assert_eq!(got.history[0].field_id, Some(got.fields[1].id));

    // Clearing the heading's value back to empty: still no history.
    v.set_field(id, heading, secret(""), 4_000).unwrap();
    assert_eq!(v.get(id).unwrap().history.len(), 1);
}

#[test]
fn section_merges_by_name_and_stamp_like_any_field() {
    let mut a = new_vault();
    a.set_device_id(Uuid::from_u128(0xAAAA));
    let mut item = Item::new("Merged", device(), 1_000);
    item.fields.push(section("Heading", 1_000));
    item.fields
        .push(Field::new("username", FieldKind::Text, secret("u"), 1_000));
    let id = a.insert(item, 1_000);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(Uuid::from_u128(0xBBBB));

    // A renames the heading (an edit of the same field, FI-1) at 2_000; B adds a second
    // heading at 3_000.
    a.update(id, 2_000, |i| i.fields[0].name = "Renamed heading".into())
        .unwrap();
    b.update(id, 3_000, |i| i.fields.push(section("Second", 3_000)))
        .unwrap();
    let r = a.merge_from(&b).unwrap();
    assert_eq!(r.updated, 1);
    let got = a.get(id).unwrap();
    let names: Vec<&str> = got.fields.iter().map(|f| f.name.as_str()).collect();
    // B won the metadata (3_000 > 2_000): B's order; the heading keeps A's newer name.
    assert_eq!(
        names,
        ["Renamed heading", "username", "Second"],
        "fields keyed by id: the rename travels, nothing is duplicated"
    );
    assert!(
        got.fields
            .iter()
            .filter(|f| f.kind == FieldKind::Section)
            .count()
            == 2
    );
    let r = b.merge_from(&a).unwrap();
    assert_eq!(r.updated, 1);
    // B's merged content changed at an equal stamp, so B bumped `+1` (merge docs); one more
    // round trip converges the stamps.
    a.merge_from(&b).unwrap();
    assert_vaults_eq(&a, &b);

    // Same heading on both sides (same id), the newer stamp wins its value.
    let second = field_named(a.get(id).unwrap(), "Second").unwrap().id;
    a.set_field(id, second, secret("a-val"), 4_000).unwrap();
    b.set_field(id, second, secret("b-val"), 5_000).unwrap();
    a.merge_from(&b).unwrap();
    assert_eq!(
        a.get(id)
            .unwrap()
            .field_by_id(second)
            .unwrap()
            .value
            .expose_secret(),
        "b-val"
    );
    assert!(
        a.get(id).unwrap().history.is_empty(),
        "no conflict history for headings"
    );
}

// -------------------------------------------------------------------------------------------
// Older fixtures
// -------------------------------------------------------------------------------------------

#[test]
fn pre_v1_3_fixtures_still_parse_unchanged_with_no_created_at() {
    const BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
    const STAMPED: &[u8] = include_bytes!("fixtures/v1-stamped.vault");
    const ICON: &[u8] = include_bytes!("fixtures/v1-icon.vault");
    for (name, bytes) in [
        ("v1-basic", BASIC),
        ("v1-stamped", STAMPED),
        ("v1-icon", ICON),
    ] {
        let file = VaultFile::parse(bytes).unwrap();
        assert_eq!(file.to_bytes(), bytes, "{name}: structural round trip");
        let v = unlock(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(v.items_including_deleted().count() > 0, "{name}: has items");
        for item in v.items_including_deleted() {
            assert_eq!(
                item.created_at, None,
                "{name}: {} has no created_at",
                item.title
            );
            assert!(
                key(&plain_map(item), "created_at").is_none(),
                "{name}: re-encoding never invents a created_at key"
            );
            assert!(
                item.fields.iter().all(|f| f.kind != FieldKind::Section),
                "{name}: no section fields before v1.3"
            );
        }
        let again = unlock(&v.serialize()).unwrap();
        assert_vaults_eq(&v, &again);
    }
}
