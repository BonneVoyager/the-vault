//! `Field.icon` (01 §4, 2026-11-07, optional key, no version bump): an app-interpreted
//! symbol name carried by a field. Round trip of every shape, the empty-string rule, null and
//! wrong-type handling, unknown-key preservation next to it, change detection in `update`,
//! whole-field merge (03 §5), the canonical-bytes tie-break, and pre-icon fixtures.

mod common;

use ciborium::Value;
use common::*;
use vault_core::format;
use vault_core::{ExposeSecret, Field, FieldKind, Item, UnlockedVault, Uuid, VaultError};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

type Entries = Vec<(Value, Value)>;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn field(name: &str, icon: Option<&str>, now: u64) -> Field {
    let mut f = Field::new(name, FieldKind::Text, secret(format!("{name} value")), now);
    f.icon = icon.map(str::to_owned);
    f
}

/// One item with the given fields, inserted at `now`.
fn item_with(fields: Vec<Field>, now: u64) -> Item {
    let mut item = Item::new("Icons", device(), now);
    item.fields = fields;
    item
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

fn field_maps(entries: &Entries) -> Vec<Entries> {
    let Some((_, Value::Array(fields))) = entries.iter().find(|(k, _)| k == &t("fields")) else {
        panic!("fields array")
    };
    fields
        .iter()
        .map(|f| match f {
            Value::Map(m) => m.clone(),
            _ => panic!("field is a map"),
        })
        .collect()
}

fn keys(entries: &Entries) -> Vec<String> {
    entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.clone(),
            _ => panic!("text key"),
        })
        .collect()
}

fn dev_a() -> Uuid {
    Uuid::from_u128(0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA)
}

fn dev_b() -> Uuid {
    Uuid::from_u128(0xBBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB_BBBB)
}

/// Two "devices" sharing one item with one icon-less field stamped 1000 by A.
fn two_devices() -> (UnlockedVault, UnlockedVault, Uuid, Uuid) {
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let f = field("username", None, 1_000);
    let fid = f.id;
    let id = a.insert(item_with(vec![f], 1_000), 1_000);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    assert_vaults_eq(&a, &b);
    (a, b, id, fid)
}

fn icon_of(v: &UnlockedVault, id: Uuid, fid: Uuid) -> Option<String> {
    v.get(id).unwrap().field_by_id(fid).unwrap().icon.clone()
}

// --- shape ---------------------------------------------------------------------------------

#[test]
fn field_new_has_no_icon() {
    assert_eq!(field("x", None, 1).icon, None);
    assert_eq!(
        Field::new("x", FieldKind::Text, secret("v"), 1).icon_name(),
        None
    );
}

#[test]
fn round_trip_keeps_the_icon_and_reads_empty_as_none() {
    let mut v = new_vault();
    let fields = vec![
        field("keyed", Some("key"), 10),
        field("absent", None, 10),
        field("empty", Some(""), 10),
    ];
    let ids: Vec<Uuid> = fields.iter().map(|f| f.id).collect();
    let id = v.insert(item_with(fields, 10), 10);
    let got = unlock(&v.serialize()).unwrap();
    let item = got.get(id).unwrap();
    assert_eq!(
        item.field_by_id(ids[0]).unwrap().icon.as_deref(),
        Some("key")
    );
    assert_eq!(item.field_by_id(ids[1]).unwrap().icon, None);
    assert_eq!(
        item.field_by_id(ids[2]).unwrap().icon,
        None,
        "Some(\"\") is written without the key and reads back as None"
    );
    for f in &item.fields {
        assert!(
            f.extras.is_empty(),
            "{}: icon never lands in extras",
            f.name
        );
        assert_eq!(f.modified_at, 10);
    }
    // Everything else about the fields survives, icon included (helper compares it).
    let twice = unlock(&got.serialize()).unwrap();
    assert_item_eq(got.get(id).unwrap(), twice.get(id).unwrap());
}

#[test]
fn icon_key_is_written_only_when_non_empty_and_sorts_after_id() {
    let mut v = new_vault();
    let id = v.insert(
        item_with(
            vec![
                field("keyed", Some("key"), 10),
                field("absent", None, 10),
                field("empty", Some(""), 10),
            ],
            10,
        ),
        10,
    );
    let maps = field_maps(&plain_map(v.get(id).unwrap()));
    assert_eq!(maps.len(), 3);
    assert_eq!(
        keys(&maps[0]),
        [
            "id",
            "icon",
            "kind",
            "name",
            "value",
            "section",
            "modified_at"
        ],
        "canonical (length, bytes) order: icon between id and kind"
    );
    assert_eq!(
        maps[0]
            .iter()
            .find(|(k, _)| k == &t("icon"))
            .map(|(_, v)| v.clone()),
        Some(t("key"))
    );
    for (i, m) in maps.iter().enumerate().skip(1) {
        assert_eq!(
            keys(m),
            ["id", "kind", "name", "value", "section", "modified_at"],
            "field {i}: no icon, no key"
        );
    }
}

#[test]
fn fields_differing_only_in_icon_serialise_differently() {
    let base = field("username", None, 10);
    let mut with = base.clone();
    with.icon = Some("key".into());
    let mut other = base.clone();
    other.icon = Some("lock".into());
    let mut empty = base.clone();
    empty.icon = Some("".into());

    let bytes = |f: &Field| format::encode_item_plain(&item_with(vec![f.clone()], 10));
    assert_ne!(
        bytes(&base).as_slice(),
        bytes(&with).as_slice(),
        "None vs Some(\"key\")"
    );
    assert_ne!(
        bytes(&with).as_slice(),
        bytes(&other).as_slice(),
        "two different icon names"
    );
    assert_eq!(
        bytes(&base).as_slice(),
        bytes(&empty).as_slice(),
        "Some(\"\") is None on the wire"
    );
}

#[test]
fn debug_prints_the_icon_and_still_redacts_the_value() {
    let f = field("username", Some("key"), 10);
    let dbg = format!("{f:?}");
    assert!(dbg.contains("icon: Some(\"key\")"), "{dbg}");
    assert!(!dbg.contains("username value"), "{dbg}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
}

// --- reader tolerance ----------------------------------------------------------------------

/// A field whose `icon` extra is written verbatim: with `icon == None` the writer does not
/// reserve the key, so this is how a null or a wrong type reaches the reader.
fn with_icon_extra(value: Value) -> (UnlockedVault, Uuid, Uuid) {
    let mut v = new_vault();
    let mut f = field("username", None, 10);
    f.extras = vec![(t("icon"), value)];
    let fid = f.id;
    let id = v.insert(item_with(vec![f], 10), 10);
    (v, id, fid)
}

#[test]
fn null_icon_reads_as_none_and_leaves_no_extra() {
    let (v, id, fid) = with_icon_extra(Value::Null);
    let maps = field_maps(&plain_map(v.get(id).unwrap()));
    assert!(
        maps[0].contains(&(t("icon"), Value::Null)),
        "the null really is on the wire"
    );
    let got = unlock(&v.serialize()).unwrap();
    let f = got.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.icon, None);
    assert!(f.extras.is_empty());
    assert_eq!(f.modified_at, 10);
}

#[test]
fn empty_icon_string_on_disk_reads_as_none() {
    let (v, id, fid) = with_icon_extra(t(""));
    let got = unlock(&v.serialize()).unwrap();
    let f = got.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.icon, None);
    assert!(f.extras.is_empty());
}

#[test]
fn non_text_icon_is_malformed() {
    for bad in [
        Value::Integer(1.into()),
        Value::Bool(true),
        Value::Bytes(vec![1, 2, 3]),
        Value::Array(vec![t("key")]),
        Value::Map(vec![(t("kind"), t("symbol"))]),
    ] {
        let (v, _, _) = with_icon_extra(bad.clone());
        match unlock(&v.serialize()) {
            Err(VaultError::Malformed(msg)) => {
                assert!(msg.contains("field.icon"), "{bad:?}: {msg}");
            }
            other => panic!("{bad:?}: expected Malformed, got {:?}", other.map(|_| ())),
        }
    }
}

#[test]
fn unknown_field_keys_are_preserved_next_to_the_icon() {
    let mut v = new_vault();
    let mut f = field("username", Some("key"), 10);
    f.extras = vec![(t("future"), t("x")), (t("zzz"), Value::Integer(7.into()))];
    let fid = f.id;
    let id = v.insert(item_with(vec![f], 10), 10);
    let got = unlock(&v.serialize()).unwrap();
    let f = got.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.icon.as_deref(), Some("key"));
    // Extras come back in canonical (length, bytes) key order.
    assert_eq!(
        f.extras,
        vec![(t("zzz"), Value::Integer(7.into())), (t("future"), t("x"))]
    );
    // A colliding `icon` extra is dropped while the field has its own icon.
    let mut v = new_vault();
    let mut f = field("username", Some("key"), 10);
    f.extras = vec![(t("icon"), t("stale"))];
    let fid = f.id;
    let id = v.insert(item_with(vec![f], 10), 10);
    let got = unlock(&v.serialize()).unwrap();
    let f = got.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.icon.as_deref(), Some("key"));
    assert!(f.extras.is_empty());
}

// --- change detection ----------------------------------------------------------------------

#[test]
fn update_changing_only_the_icon_restamps_the_field() {
    let mut v = new_vault();
    let f = field("username", None, 10);
    let fid = f.id;
    let id = v.insert(item_with(vec![f], 10), 10);

    v.update(id, 20, |i| {
        i.fields.iter_mut().find(|f| f.id == fid).unwrap().icon = Some("key".into());
    })
    .unwrap();
    let item = v.get(id).unwrap();
    let f = item.field_by_id(fid).unwrap();
    assert_eq!(f.icon.as_deref(), Some("key"));
    assert_eq!(f.modified_at, 20, "icon-only edit bumps the field");
    assert_eq!(item.modified_at, 20);
    assert_eq!(
        f.value.expose_secret(),
        "username value",
        "nothing else moved"
    );

    // Changing the name of the icon is a change too.
    v.update(id, 30, |i| {
        i.fields.iter_mut().find(|f| f.id == fid).unwrap().icon = Some("lock".into());
    })
    .unwrap();
    assert_eq!(v.get(id).unwrap().field_by_id(fid).unwrap().modified_at, 30);

    // Clearing it is a change.
    v.update(id, 40, |i| {
        i.fields.iter_mut().find(|f| f.id == fid).unwrap().icon = None;
    })
    .unwrap();
    assert_eq!(v.get(id).unwrap().field_by_id(fid).unwrap().modified_at, 40);

    // `None -> Some("")` is not: it is "no icon" both before and after (never written).
    v.update(id, 50, |i| {
        i.fields.iter_mut().find(|f| f.id == fid).unwrap().icon = Some(String::new());
    })
    .unwrap();
    let f = v.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.modified_at, 40, "Some(\"\") is not a change");
    assert_eq!(f.icon.as_deref(), Some(""), "kept in memory as given");
    assert_eq!(f.icon_name(), None);
    assert_eq!(
        unlock(&v.serialize())
            .unwrap()
            .get(id)
            .unwrap()
            .field_by_id(fid)
            .unwrap()
            .icon,
        None
    );
}

#[test]
fn update_respects_a_stamp_the_caller_already_bumped() {
    let mut v = new_vault();
    let f = field("username", None, 10);
    let fid = f.id;
    let id = v.insert(item_with(vec![f], 10), 10);
    v.update(id, 20, |i| {
        let f = i.fields.iter_mut().find(|f| f.id == fid).unwrap();
        f.icon = Some("key".into());
        f.modified_at = 15;
    })
    .unwrap();
    let f = v.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.modified_at, 15, "caller-provided stamp is kept");
    assert_eq!(f.icon.as_deref(), Some("key"));
}

#[test]
fn set_field_keeps_the_icon() {
    let mut v = new_vault();
    let f = field("username", Some("key"), 10);
    let fid = f.id;
    let id = v.insert(item_with(vec![f], 10), 10);
    v.set_field(id, fid, secret("new"), 20).unwrap();
    let f = v.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.value.expose_secret(), "new");
    assert_eq!(f.icon.as_deref(), Some("key"));
    assert_eq!(f.modified_at, 20);
}

// --- merge (03 §5: whole-field LWW, the icon travels with the winner) --------------------------

#[test]
fn merge_newer_field_with_icon_beats_older_without() {
    let (mut a, mut b, id, fid) = two_devices();
    a.update(id, 2_000, |i| {
        i.fields.iter_mut().find(|f| f.id == fid).unwrap().icon = Some("key".into());
    })
    .unwrap();
    // B merges A: takes the icon.
    let report = b.merge_from(&a).unwrap();
    assert_eq!(report.updated, 1, "{report:?}");
    assert_eq!(icon_of(&b, id, fid).as_deref(), Some("key"));
    assert_eq!(
        b.get(id).unwrap().field_by_id(fid).unwrap().modified_at,
        2_000
    );
    // A merges B (older, no icon): keeps the icon, nothing changes.
    let report = a.merge_from(&b).unwrap();
    assert!(!report.changed(), "{report:?}");
    assert_eq!(icon_of(&a, id, fid).as_deref(), Some("key"));
    assert_vaults_eq(&a, &b);
}

#[test]
fn merge_newer_field_without_icon_beats_older_with() {
    let (mut a, mut b, id, fid) = two_devices();
    a.update(id, 2_000, |i| {
        i.fields.iter_mut().find(|f| f.id == fid).unwrap().icon = Some("key".into());
    })
    .unwrap();
    // B edits the value later, without ever seeing the icon.
    b.set_field(id, fid, secret("newer"), 3_000).unwrap();
    assert_eq!(icon_of(&b, id, fid), None);

    let report = a.merge_from(&b).unwrap();
    assert_eq!(report.updated, 1, "{report:?}");
    let f = a.get(id).unwrap().field_by_id(fid).unwrap();
    assert_eq!(f.icon, None, "the whole newer field wins, icon included");
    assert_eq!(f.value.expose_secret(), "newer");
    assert_eq!(f.modified_at, 3_000);
    // The other direction: B merging A's older icon-only edit changes nothing.
    let report = b.merge_from(&a).unwrap();
    assert!(!report.changed(), "{report:?}");
    assert_vaults_eq(&a, &b);
}

#[test]
fn merge_icon_only_edit_on_one_side_converges_both_ways() {
    // The icon change is the only difference; the stamp carries it either way round.
    let (mut a, mut b, id, fid) = two_devices();
    b.update(id, 2_000, |i| {
        i.fields.iter_mut().find(|f| f.id == fid).unwrap().icon = Some("lock".into());
    })
    .unwrap();
    let a_snap = unlock(&a.serialize()).unwrap();
    let b_snap = unlock(&b.serialize()).unwrap();
    a.merge_from(&b_snap).unwrap();
    b.merge_from(&a_snap).unwrap();
    assert_eq!(icon_of(&a, id, fid).as_deref(), Some("lock"));
    assert_eq!(icon_of(&b, id, fid).as_deref(), Some("lock"));
    assert_vaults_eq(&a, &b);
}

#[test]
fn merge_equal_stamp_and_device_breaks_the_tie_on_canonical_bytes_symmetrically() {
    // Same item, same device id, same stamp, differing only in the icon: both sides must
    // pick the same field (03 §5 third tie-break), whichever direction merges.
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let f = field("username", Some("aaa"), 1_000);
    let fid = f.id;
    let id = a.insert(item_with(vec![f], 1_000), 1_000);
    // A twin of A holding the same item (same id, device, stamp) whose field differs only in
    // the icon. `update` would bump the stamp of a changed field (the restamp rule), so the
    // twin is built by emptying a copy of A and re-inserting the item at the same stamp.
    let mut b = unlock(&a.serialize()).unwrap();
    b.delete(id, 1_000).unwrap();
    b.purge_tombstones_older_than(u64::MAX);
    let mut twin = a.get(id).unwrap().clone();
    twin.fields[0].icon = Some("zzz".into());
    assert_eq!(b.insert(twin, 1_000), id);
    let b = unlock(&b.serialize()).unwrap();
    let b_item = b.get(id).unwrap();
    assert_eq!(b_item.field_by_id(fid).unwrap().modified_at, 1_000);
    let mut b2 = unlock(&b.serialize()).unwrap();
    let a_snap = unlock(&a.serialize()).unwrap();
    a.merge_from(&b).unwrap();
    b2.merge_from(&a_snap).unwrap();
    assert_eq!(
        icon_of(&a, id, fid),
        icon_of(&b2, id, fid),
        "both directions pick the same icon"
    );
    assert_eq!(
        a.get(id)
            .unwrap()
            .field_by_id(fid)
            .unwrap()
            .value
            .expose_secret(),
        b2.get(id)
            .unwrap()
            .field_by_id(fid)
            .unwrap()
            .value
            .expose_secret()
    );
}

// --- forward compatibility -----------------------------------------------------------------

#[test]
fn pre_icon_fixtures_read_every_field_as_icon_less() {
    for name in ["v1-meta.vault", "v2-meta.vault", "v2-basic.vault"] {
        let bytes = std::fs::read(format!("{FIXTURE_DIR}/{name}")).unwrap();
        let v = unlock(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut fields = 0;
        for item in v.items_including_deleted() {
            for f in &item.fields {
                fields += 1;
                assert_eq!(f.icon, None, "{name}: {}", f.name);
                assert!(
                    !f.extras.iter().any(|(k, _)| k == &t("icon")),
                    "{name}: no icon extra"
                );
            }
        }
        assert!(fields > 0, "{name}: has fields");
    }
}
