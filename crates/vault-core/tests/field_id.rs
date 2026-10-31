//! Field identity (FI-1, format version 2): `Field::id`, the version 1 migration
//! (`Field::derived_id`), `removed_fields` markers, `HistoryEntry::field_id`, merge by id
//! (03 §5, including the closed "field deletion resurrection" limit), and the API around
//! them (02 `update`, `set_field`, `set_field_named`, `remove_field`, `upgrade_format`).

mod common;

use ciborium::Value;
use common::*;
use vault_core::format::{self, MIN_FORMAT_VERSION, VaultFile};
use vault_core::vault::FIELD_TOMBSTONE_CAP;
use vault_core::vault::merge::item_eq;
use vault_core::{
    ExposeSecret, FORMAT_VERSION, Field, FieldKind, FieldTombstone, HistoryEntry, Item,
    LockedVault, SecretVec, UnlockedVault, Uuid, VaultError,
};

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

/// Two "devices" holding the same vault with one sample item at t=1000.
fn two_devices() -> (UnlockedVault, UnlockedVault, Uuid) {
    let mut a = new_vault();
    a.set_device_id(dev_a());
    let id = a.insert(sample_item(0, 1_000), 1_000);
    let mut b = unlock(&a.serialize()).unwrap();
    b.set_device_id(dev_b());
    assert_vaults_eq(&a, &b);
    (a, b, id)
}

/// Merge both ways from snapshots, twice, and assert convergence and idempotence (see
/// `tests/merge.rs::converge`).
fn converge(a: &mut UnlockedVault, b: &mut UnlockedVault) {
    for _ in 0..2 {
        let a_snap = unlock(&a.serialize()).unwrap();
        let b_snap = unlock(&b.serialize()).unwrap();
        a.merge_from(&b_snap).unwrap();
        b.merge_from(&a_snap).unwrap();
        assert!(!a.merge_from(&b_snap).unwrap().changed(), "idempotent on A");
        assert!(!b.merge_from(&a_snap).unwrap().changed(), "idempotent on B");
    }
    assert_vaults_eq(a, b);
}

fn fid(v: &UnlockedVault, id: Uuid, name: &str) -> Uuid {
    v.get(id).unwrap().field(name).unwrap().id
}

fn value(v: &UnlockedVault, id: Uuid, field_id: Uuid) -> String {
    v.get(id)
        .unwrap()
        .field_by_id(field_id)
        .unwrap()
        .value
        .expose_secret()
        .clone()
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

fn keys(entries: &Entries) -> Vec<String> {
    entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.clone(),
            _ => panic!("text keys"),
        })
        .collect()
}

fn set_key(entries: &mut Entries, k: &str, v: Value) {
    match entries.iter_mut().find(|(kk, _)| kk == &t(k)) {
        Some((_, slot)) => *slot = v,
        None => entries.push((t(k), v)),
    }
}

fn del_key(entries: &mut Entries, k: &str) {
    entries.retain(|(kk, _)| kk != &t(k));
}

/// Edit the `idx`-th field map inside an `ItemPlain` map.
fn edit_field(entries: &mut Entries, idx: usize, f: impl FnOnce(&mut Entries)) {
    let Some((_, Value::Array(fields))) = entries.iter_mut().find(|(k, _)| k == &t("fields"))
    else {
        panic!("fields array")
    };
    let Value::Map(field) = &mut fields[idx] else {
        panic!("field map")
    };
    f(field);
}

/// Re-encode an item's plaintext after editing the map, then decode it under `version`.
fn reencode(
    item: &Item,
    version: u16,
    edit: impl FnOnce(&mut Entries),
) -> Result<Item, VaultError> {
    let mut entries = plain_map(item);
    edit(&mut entries);
    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut buf).unwrap();
    format::decode_item_plain(&buf, item.id, item.modified_at, version)
}

fn field_maps(entries: &Entries) -> Vec<Entries> {
    let Some(Value::Array(fields)) = key(entries, "fields") else {
        panic!("fields array")
    };
    fields
        .into_iter()
        .map(|f| match f {
            Value::Map(m) => m,
            _ => panic!("field map"),
        })
        .collect()
}

// -------------------------------------------------------------------------------------------
// ids on disk
// -------------------------------------------------------------------------------------------

#[test]
fn ids_round_trip_with_duplicate_and_empty_names() {
    let mut v = new_vault();
    let mut item = Item::new("Dupes", device(), 10);
    item.fields = vec![
        Field::new("username", FieldKind::Text, secret("first"), 10),
        Field::new("Username", FieldKind::Section, secret(""), 10),
        Field::new("username", FieldKind::Text, secret("second"), 10),
        Field::new("", FieldKind::Text, secret("unnamed"), 10),
        Field::new("", FieldKind::Password, secret("unnamed pw"), 10),
    ];
    let ids: Vec<Uuid> = item.fields.iter().map(|f| f.id).collect();
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        5,
        "Field::new gives every field a distinct v4 id"
    );
    assert!(ids.iter().all(|id| id.get_version_num() == 4));
    let id = v.insert(item, 10);

    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    let got = u.get(id).unwrap();
    assert_eq!(got.fields.iter().map(|f| f.id).collect::<Vec<_>>(), ids);
    assert_eq!(
        got.field("username").unwrap().id,
        ids[0],
        "first non-section"
    );
    assert_eq!(
        got.field("USERNAME").unwrap().id,
        ids[0],
        "ASCII case-insensitive"
    );
    assert!(
        got.field("").is_none(),
        "an empty name never matches a lookup"
    );
    assert_eq!(
        got.field_by_id(ids[3]).unwrap().value.expose_secret(),
        "unnamed"
    );
    assert_eq!(got.field_by_id(ids[1]).unwrap().kind, FieldKind::Section);
    assert!(item_eq(v.get(id).unwrap(), got));

    // Export and search still work; the empty-named field is simply never found by name.
    let csv = vault_core::export_csv(&u);
    let text = String::from_utf8(csv.0.clone()).unwrap();
    // `username` by name finds the first one; `password` by name finds nothing, so the
    // by-kind fallback picks the unnamed password field; the unnamed text field has no
    // column (no name lookup can reach it).
    assert!(text.contains("Dupes,first,unnamed pw,,,"), "{text}");
    assert!(
        !text.contains("unnamed value"),
        "no column maps to an empty name"
    );
}

#[test]
fn field_map_has_id_first_and_item_keys_gain_removed_fields_only_when_present() {
    let mut v = new_vault();
    let id = v.insert(sample_item(1, 10), 10);
    let entries = plain_map(v.get(id).unwrap());
    let fields = field_maps(&entries);
    assert_eq!(fields.len(), 5);
    for (i, f) in fields.iter().enumerate() {
        assert_eq!(
            keys(f),
            ["id", "kind", "name", "value", "section", "modified_at"],
            "field {i}: canonical order, id first"
        );
        assert_eq!(
            key(f, "id"),
            Some(Value::Bytes(
                v.get(id).unwrap().fields[i].id.as_bytes().to_vec()
            )),
            "id is bytes(16)"
        );
    }
    assert!(
        key(&entries, "removed_fields").is_none(),
        "no markers, no key"
    );
    assert_eq!(
        keys(&entries),
        [
            "tags",
            "title",
            "fields",
            "history",
            "favorite",
            "device_id",
            "created_at",
            "deleted_at",
            "attachments"
        ]
    );

    let pin = fid(&v, id, "notes");
    v.remove_field(id, pin, 20).unwrap();
    v.remove_history_entry(id, 900, 21).unwrap_err(); // no such entry on item 1: unchanged
    let entries = plain_map(v.get(id).unwrap());
    assert_eq!(
        key(&entries, "removed_fields"),
        Some(Value::Array(vec![Value::Map(vec![
            (t("id"), Value::Bytes(pin.as_bytes().to_vec())),
            (t("removed_at"), Value::Integer(20.into())),
        ])])),
        "exact shape: [{{ id: bytes(16), removed_at: u64 }}]"
    );
    assert_eq!(
        keys(&entries),
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
            "removed_fields"
        ],
        "sorts between attachments and removed_history"
    );
    let u = unlock(&v.serialize()).unwrap();
    assert_eq!(
        u.get(id).unwrap().removed_fields,
        vec![FieldTombstone {
            id: pin,
            removed_at: 20
        }]
    );
    assert!(u.get(id).unwrap().field_by_id(pin).is_none());
    assert_vaults_eq(&v, &u);
}

#[test]
fn removed_fields_null_missing_and_bad_shapes() {
    let mut v = new_vault();
    let id = v.insert(sample_item(1, 10), 10);
    v.remove_field(id, fid(&v, id, "notes"), 20).unwrap();
    let item = v.get(id).unwrap();
    let null = reencode(item, FORMAT_VERSION, |e| {
        set_key(e, "removed_fields", Value::Null)
    })
    .unwrap();
    assert!(null.removed_fields.is_empty());
    let missing = reencode(item, FORMAT_VERSION, |e| del_key(e, "removed_fields")).unwrap();
    assert!(missing.removed_fields.is_empty());
    assert_eq!(missing.fields.len(), 4, "fields themselves untouched");
    for (what, bad) in [
        ("not an array", Value::Integer(1.into())),
        (
            "entry not a map",
            Value::Array(vec![Value::Integer(1.into())]),
        ),
        (
            "missing removed_at",
            Value::Array(vec![Value::Map(vec![(t("id"), Value::Bytes(vec![1; 16]))])]),
        ),
        (
            "short id",
            Value::Array(vec![Value::Map(vec![
                (t("id"), Value::Bytes(vec![1; 15])),
                (t("removed_at"), Value::Integer(1.into())),
            ])]),
        ),
    ] {
        let r = reencode(item, FORMAT_VERSION, |e| set_key(e, "removed_fields", bad));
        assert!(matches!(r, Err(VaultError::Malformed(_))), "{what}");
    }
}

#[test]
fn version_2_requires_field_ids_and_rejects_bad_or_duplicate_ones() {
    let mut v = new_vault();
    let id = v.insert(sample_item(2, 10), 10);
    let item = v.get(id).unwrap();

    // Missing id: Malformed under version 2, derived under version 1.
    let r = reencode(item, FORMAT_VERSION, |e| {
        edit_field(e, 1, |f| del_key(f, "id"))
    });
    assert!(
        matches!(&r, Err(VaultError::Malformed(m)) if m.contains("id")),
        "{r:?}"
    );
    let migrated = reencode(item, 1, |e| edit_field(e, 1, |f| del_key(f, "id"))).unwrap();
    assert_eq!(
        migrated.fields[1].id,
        Field::derived_id(item.id, "password", 0),
        "version 1: derived"
    );
    assert_eq!(
        migrated.fields[0].id, item.fields[0].id,
        "explicit ids are kept"
    );

    // Null, wrong type or wrong length: Malformed under both versions.
    for version in [1, FORMAT_VERSION] {
        for (what, bad) in [
            ("null", Value::Null),
            ("text", t("not bytes")),
            ("15 bytes", Value::Bytes(vec![7; 15])),
            ("17 bytes", Value::Bytes(vec![7; 17])),
        ] {
            let r = reencode(item, version, |e| {
                edit_field(e, 0, |f| set_key(f, "id", bad))
            });
            assert!(
                matches!(r, Err(VaultError::Malformed(_))),
                "version {version}, {what}"
            );
        }
        // Two fields with the same id.
        let dup = Value::Bytes(item.fields[0].id.as_bytes().to_vec());
        let r = reencode(item, version, |e| {
            edit_field(e, 1, |f| set_key(f, "id", dup))
        });
        assert!(
            matches!(&r, Err(VaultError::Malformed(m)) if m.contains("duplicate field id")),
            "version {version}: {r:?}"
        );
    }
    // Under version 1 an explicit id that collides with a derived one is a duplicate too.
    let derived = Value::Bytes(
        Field::derived_id(item.id, "username", 0)
            .as_bytes()
            .to_vec(),
    );
    let r = reencode(item, 1, |e| {
        edit_field(e, 0, |f| del_key(f, "id"));
        edit_field(e, 2, |f| set_key(f, "id", derived));
    });
    assert!(matches!(r, Err(VaultError::Malformed(_))));
}

// -------------------------------------------------------------------------------------------
// version 1 migration
// -------------------------------------------------------------------------------------------

#[test]
fn v1_migration_is_deterministic_and_matches_the_uuid_v5_formula() {
    const BASIC: &[u8] = include_bytes!("fixtures/v1-basic.vault");
    const META: &[u8] = include_bytes!("fixtures/v1-meta.vault");
    const FORWARD: &[u8] = include_bytes!("fixtures/v1-forward.vault");
    for (name, bytes) in [("basic", BASIC), ("meta", META), ("forward", FORWARD)] {
        let first = unlock(bytes).unwrap();
        let second = unlock(bytes).unwrap();
        assert_vaults_eq(&first, &second);
        assert_eq!(first.header().format_version, 1);
        for item in first.items_including_deleted() {
            assert!(!item.fields.is_empty(), "{name}: {} has fields", item.title);
            for (i, f) in item.fields.iter().enumerate() {
                let ordinal = item.fields[..i].iter().filter(|e| e.name == f.name).count();
                let expected =
                    Uuid::new_v5(&item.id, format!("field:{}:{ordinal}", f.name).as_bytes());
                assert_eq!(f.id, expected, "{name}: {}/{}", item.title, f.name);
                assert_eq!(f.id, Field::derived_id(item.id, &f.name, ordinal));
                assert_eq!(f.id.get_version_num(), 5);
            }
        }
        // A save writes the ids explicitly (still version 1) and a reload keeps them; a
        // second device reading the original file agrees with the saved one.
        let saved = first.serialize();
        assert_eq!(&saved[4..6], &[0, 1], "{name}: a v1 file stays v1");
        let reopened = unlock(&saved).unwrap();
        assert_vaults_eq(&first, &reopened);
        assert_vaults_eq(&second, &reopened);
    }

    // Ordinals: a hand-built v1 payload with three `username` fields (and one `Username`,
    // which is a different name byte-wise) numbers them 0, 1, 2 / 0.
    let mut item = Item::new("ordinals", device(), 5);
    for (i, n) in ["username", "username", "Username", "username"]
        .iter()
        .enumerate()
    {
        item.fields
            .push(Field::new(*n, FieldKind::Text, secret(format!("v{i}")), 5));
    }
    let migrated = reencode(&item, 1, |e| {
        for i in 0..4 {
            edit_field(e, i, |f| del_key(f, "id"));
        }
    })
    .unwrap();
    let got: Vec<Uuid> = migrated.fields.iter().map(|f| f.id).collect();
    assert_eq!(
        got,
        [
            Field::derived_id(item.id, "username", 0),
            Field::derived_id(item.id, "username", 1),
            Field::derived_id(item.id, "Username", 0),
            Field::derived_id(item.id, "username", 2),
        ]
    );
    // Mixed: an explicit id on field 1 still counts for field 3's ordinal.
    let keep = item.fields[1].id;
    let mixed = reencode(&item, 1, |e| {
        for i in [0, 2, 3] {
            edit_field(e, i, |f| del_key(f, "id"));
        }
    })
    .unwrap();
    assert_eq!(mixed.fields[1].id, keep);
    assert_eq!(
        mixed.fields[3].id,
        Field::derived_id(item.id, "username", 2)
    );
}

#[test]
fn new_vaults_are_version_2_and_version_1_still_reads() {
    assert_eq!(FORMAT_VERSION, 2);
    assert_eq!(MIN_FORMAT_VERSION, 1);
    let v = new_vault();
    assert_eq!(v.header().format_version, 2);
    let bytes = v.serialize();
    assert_eq!(&bytes[4..6], &[0, 2], "prefix version 2");
    assert_eq!(VaultFile::parse(&bytes).unwrap().header.format_version, 2);
    assert!(unlock(&bytes).is_ok());

    // Version 1 still parses and unlocks; a save keeps it at 1; version 3 is refused.
    let mut v1 = unstamped_vault();
    assert_eq!(v1.header().format_version, 1);
    let id = v1.insert(sample_item(3, 10), 10);
    let again = v1.serialize();
    assert_eq!(&again[4..6], &[0, 1]);
    let re = unlock(&again).unwrap();
    assert_eq!(re.header().format_version, 1);
    assert_vaults_eq(&v1, &re);
    assert_eq!(re.get(id).unwrap().fields.len(), 5);
    let mut v3 = again.clone();
    v3[5] = 3;
    assert_eq!(
        LockedVault::parse(&v3).unwrap_err(),
        VaultError::UnsupportedVersion(3)
    );
}

#[test]
fn upgrade_format_rewraps_password_slots_drops_the_rest_and_is_idempotent() {
    let mut v = unstamped_vault();
    let id = v.insert(sample_item(4, 10), 10);
    let ids: Vec<Uuid> = v.get(id).unwrap().fields.iter().map(|f| f.id).collect();
    let kek = SecretVec::new(vec![0x42; 32]);
    let enclave = v.add_enclave_slot(&kek, 20);
    assert_eq!(v.slots().count(), 2);
    let stamp_before = v.header().slots_stamp();

    // Wrong password: untouched.
    assert_eq!(
        v.upgrade_format(&secret("nope"), 30).unwrap_err(),
        VaultError::WrongPassword
    );
    assert_eq!(v.header().format_version, 1);
    assert_eq!(v.slots().count(), 2);

    v.upgrade_format(&pw(), 30).unwrap();
    assert_eq!(v.header().format_version, 2);
    assert_eq!(
        v.slots().map(|(_, k)| k).collect::<Vec<_>>(),
        [vault_core::SlotKind::Password],
        "enclave slot dropped: its KEK cannot be re-wrapped under the new AAD"
    );
    assert!(v.header().slots_stamp() > stamp_before, "header stamped");
    let bytes = v.serialize();
    assert_eq!(&bytes[4..6], &[0, 2]);
    let locked = LockedVault::parse(&bytes).unwrap();
    assert_eq!(
        locked.unlock(&secret("nope")).unwrap_err(),
        VaultError::WrongPassword
    );
    assert!(matches!(
        locked.unlock_with_kek(enclave, &kek).unwrap_err(),
        VaultError::Malformed(_)
    ));
    let re = locked.unlock(&pw()).unwrap();
    assert_eq!(re.header().format_version, 2);
    assert_vaults_eq(&v, &re);
    assert_eq!(
        re.get(id)
            .unwrap()
            .fields
            .iter()
            .map(|f| f.id)
            .collect::<Vec<_>>(),
        ids,
        "ids unchanged by the upgrade"
    );

    // Already current: no-op, no KDF, no stamp change (a wrong password is not even checked).
    let stamp = v.header().slots_stamp();
    v.upgrade_format(&secret("whatever"), 40).unwrap();
    assert_eq!(v.header().slots_stamp(), stamp);
    assert_eq!(new_vault().upgrade_format(&secret("x"), 1), Ok(()));
}

// -------------------------------------------------------------------------------------------
// merge by id
// -------------------------------------------------------------------------------------------

#[test]
fn merge_by_id_rename_on_a_and_value_edit_on_b_converge_to_one_field() {
    let (mut a, mut b, id) = two_devices();
    let username = fid(&a, id, "username");
    a.update(id, 2_000, |i| {
        i.fields.iter_mut().find(|f| f.id == username).unwrap().name = "login".into();
    })
    .unwrap();
    assert_eq!(
        a.get(id)
            .unwrap()
            .field_by_id(username)
            .unwrap()
            .modified_at,
        2_000,
        "a rename is an edit of the same field"
    );
    b.set_field(id, username, secret("bob@example.com"), 3_000)
        .unwrap();
    converge(&mut a, &mut b);
    for v in [&a, &b] {
        let item = v.get(id).unwrap();
        assert_eq!(item.fields.len(), 5, "no duplicate from the rename");
        let f = item.field_by_id(username).unwrap();
        assert_eq!(
            f.value.expose_secret(),
            "bob@example.com",
            "B's newer value"
        );
        assert_eq!(
            f.name, "username",
            "whole-field LWW: B's field (name included) won"
        );
        assert_eq!(f.modified_at, 3_000);
        assert!(item.removed_fields.is_empty());
    }

    // The other way round: the rename is newer, so the renamed field with A's name and
    // value wins whole; nothing is duplicated either.
    let (mut a, mut b, id) = two_devices();
    let username = fid(&a, id, "username");
    b.set_field(id, username, secret("bob@example.com"), 2_000)
        .unwrap();
    a.update(id, 3_000, |i| {
        i.fields.iter_mut().find(|f| f.id == username).unwrap().name = "login".into();
    })
    .unwrap();
    converge(&mut a, &mut b);
    let f = a.get(id).unwrap().field_by_id(username).unwrap();
    assert_eq!(f.name, "login");
    assert_eq!(f.value.expose_secret(), "user0@example.com");
    assert_eq!(a.get(id).unwrap().fields.len(), 5);
    assert_eq!(a.get(id).unwrap().field("login").unwrap().id, username);
}

#[test]
fn tombstone_drops_the_field_on_the_other_device() {
    let (mut a, mut b, id) = two_devices();
    let notes = fid(&a, id, "notes");
    a.remove_field(id, notes, 2_000).unwrap();
    assert!(a.get(id).unwrap().field_by_id(notes).is_none());
    assert_eq!(
        a.get(id).unwrap().removed_fields,
        vec![FieldTombstone {
            id: notes,
            removed_at: 2_000
        }]
    );
    // B's untouched copy: the field does not come back; B learns the marker.
    let a_snap = unlock(&a.serialize()).unwrap();
    let r = b.merge_from(&a_snap).unwrap();
    assert_eq!(r.updated, 1);
    assert!(b.get(id).unwrap().field_by_id(notes).is_none());
    assert_eq!(
        b.get(id).unwrap().removed_fields,
        a.get(id).unwrap().removed_fields
    );
    assert_eq!(b.get(id).unwrap().fields.len(), 4);
    converge(&mut a, &mut b);
    assert_eq!(a.get(id).unwrap().fields.len(), 4);

    // B edited the field *before* the removal (1_500 < 2_000): still dropped on both sides.
    let (mut a, mut b, id) = two_devices();
    let notes = fid(&a, id, "notes");
    b.set_field(id, notes, secret("edited earlier"), 1_500)
        .unwrap();
    a.remove_field(id, notes, 2_000).unwrap();
    converge(&mut a, &mut b);
    for v in [&a, &b] {
        assert!(v.get(id).unwrap().field_by_id(notes).is_none());
        assert_eq!(v.get(id).unwrap().removed_fields.len(), 1);
    }

    // A removal stamped exactly at the field's stamp (`removed_at >= modified_at`) drops
    // it too: the tie goes to the removal.
    let (mut a, mut b, id) = two_devices();
    let notes = fid(&a, id, "notes");
    b.set_field(id, notes, secret("same ms"), 2_000).unwrap();
    a.update(id, 2_000, |i| i.fields.retain(|f| f.id != notes))
        .unwrap();
    assert_eq!(a.get(id).unwrap().removed_fields[0].removed_at, 2_000);
    converge(&mut a, &mut b);
    assert!(a.get(id).unwrap().field_by_id(notes).is_none());
}

#[test]
fn edit_after_delete_resurrects_the_field_and_drops_the_marker() {
    let (mut a, mut b, id) = two_devices();
    let notes = fid(&a, id, "notes");
    a.remove_field(id, notes, 2_000).unwrap();
    b.set_field(id, notes, secret("edited later"), 2_500)
        .unwrap();
    converge(&mut a, &mut b);
    for v in [&a, &b] {
        let item = v.get(id).unwrap();
        let f = item.field_by_id(notes).unwrap();
        assert_eq!(f.value.expose_secret(), "edited later");
        assert_eq!(f.modified_at, 2_500);
        assert!(
            item.removed_fields.is_empty(),
            "marker dropped on both sides"
        );
        assert_eq!(item.fields.len(), 5);
    }
    // Idempotent and stable: a further round changes nothing.
    let a_snap = unlock(&a.serialize()).unwrap();
    assert!(!b.merge_from(&a_snap).unwrap().changed());

    // Removing again afterwards sticks (the new marker is newer than the edit).
    a.remove_field(id, notes, 3_000).unwrap();
    converge(&mut a, &mut b);
    assert!(b.get(id).unwrap().field_by_id(notes).is_none());
    assert_eq!(b.get(id).unwrap().removed_fields[0].removed_at, 3_000);
}

#[test]
fn removed_field_conflict_losers_do_not_enter_history() {
    // A removes the password field, B changes it earlier: the field is dropped and B's
    // losing value is not pushed to history (the field no longer exists), while B's own
    // history entry from its edit is still unioned.
    let (mut a, mut b, id) = two_devices();
    let password = fid(&a, id, "password");
    b.set_field(id, password, secret("b-pw"), 1_500).unwrap();
    a.remove_field(id, password, 2_000).unwrap();
    converge(&mut a, &mut b);
    let item = a.get(id).unwrap();
    assert!(item.field_by_id(password).is_none());
    let values: Vec<&str> = item
        .history
        .iter()
        .map(|h| h.value.expose_secret().as_str())
        .collect();
    assert!(!values.contains(&"b-pw"), "{values:?}");
    assert!(
        values.contains(&"p\u{e4}ss-0-hunter2"),
        "B's set_field entry: {values:?}"
    );
}

#[test]
fn tombstone_cap_is_soft_locally_purge_and_normalisation() {
    let mut v = new_vault();
    let mut item = Item::new("Many", device(), 10);
    for i in 0..(FIELD_TOMBSTONE_CAP + 6) {
        item.fields.push(Field::new(
            format!("f{i}"),
            FieldKind::Text,
            secret("x"),
            10,
        ));
    }
    let ids: Vec<Uuid> = item.fields.iter().map(|f| f.id).collect();
    let id = v.insert(item, 10);
    for (i, f) in ids.iter().enumerate() {
        v.remove_field(id, *f, 100 + i as u64).unwrap();
    }
    let item = v.get(id).unwrap();
    assert!(item.fields.is_empty());
    // A local removal never drops a marker by count: only a merge that finds the field
    // absent on both sides may (bug hunt 2026-10-31 L1), see `tests/merge_hunt.rs`.
    assert_eq!(
        item.removed_fields.len(),
        FIELD_TOMBSTONE_CAP + 6,
        "over the cap locally"
    );
    assert!(
        item.removed_fields
            .windows(2)
            .all(|w| w[0].removed_at > w[1].removed_at),
        "newest first"
    );
    assert_eq!(item.removed_fields[0].removed_at, 100 + 69);
    assert_eq!(item.modified_at, 169);
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);

    // Purge drops markers strictly older than the cutoff, no restamp, no item removed.
    assert_eq!(v.purge_tombstones_older_than(150), 0);
    let item = v.get(id).unwrap();
    assert_eq!(item.removed_fields.len(), 20);
    assert!(item.removed_fields.iter().all(|t| t.removed_at >= 150));
    assert_eq!(item.modified_at, 169);

    // insert normalises a caller-built list: one marker per id (greatest stamp), newest
    // first, not truncated; and a live field with a marker wins (lifted past it, marker
    // dropped).
    let mut raw = Item::new("Raw", device(), 10);
    let live = Field::new("alive", FieldKind::Text, secret("v"), 10);
    let live_id = live.id;
    raw.fields.push(live);
    let dup = Uuid::from_u128(0x77);
    raw.removed_fields = vec![
        FieldTombstone {
            id: dup,
            removed_at: 5,
        },
        FieldTombstone {
            id: dup,
            removed_at: 9,
        },
        FieldTombstone {
            id: live_id,
            removed_at: 50,
        },
    ];
    for i in 0..FIELD_TOMBSTONE_CAP as u128 {
        raw.removed_fields.push(FieldTombstone {
            id: Uuid::from_u128(0x1000 + i),
            removed_at: 20 + i as u64,
        });
    }
    let rid = v.insert(raw, 10);
    let got = v.get(rid).unwrap();
    assert_eq!(got.removed_fields.len(), FIELD_TOMBSTONE_CAP + 1);
    assert!(
        got.removed_fields.iter().all(|t| t.id != live_id),
        "live field wins"
    );
    assert_eq!(got.fields[0].modified_at, 51, "lifted to stamp(now=10, 50)");
    assert_eq!(got.modified_at, 51);
    assert_eq!(
        got.removed_fields.iter().filter(|t| t.id == dup).count(),
        1,
        "one marker per id"
    );
    assert_eq!(
        got.removed_fields.last().unwrap().removed_at,
        9,
        "the greater stamp"
    );
    assert_eq!(got.removed_fields[0].removed_at, 20 + 63);
}

// -------------------------------------------------------------------------------------------
// update / set_field / remove_field
// -------------------------------------------------------------------------------------------

#[test]
fn update_creates_tombstones_bumps_changed_fields_and_treats_rename_as_edit() {
    let mut v = new_vault();
    let id = v.insert(sample_item(5, 1_000), 1_000);
    let before = v.get(id).unwrap().clone();
    let username = before.field("username").unwrap().id;
    let totp = before.field("totp").unwrap().id;
    let url = before.field("url").unwrap().id;
    let notes = before.field("notes").unwrap().id;
    v.update(id, 2_000, |i| {
        // rename (same id, timestamp untouched) -> bumped
        i.fields.iter_mut().find(|f| f.id == username).unwrap().name = "login".into();
        // explicit stamp on a value change -> kept
        let t = i.fields.iter_mut().find(|f| f.id == totp).unwrap();
        t.value = secret("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
        t.modified_at = 1_500;
        // removed -> marker
        i.fields.retain(|f| f.id != notes);
        // new field with id 0 stamp -> now
        i.fields
            .push(Field::new("pin", FieldKind::Text, secret("1234"), 0));
    })
    .unwrap();
    let after = v.get(id).unwrap();
    let f = after.field_by_id(username).unwrap();
    assert_eq!(f.name, "login");
    assert_eq!(f.modified_at, 2_000, "rename bumped the same field");
    assert!(after.field("username").is_none());
    assert_eq!(after.field("login").unwrap().id, username, "identity kept");
    assert_eq!(after.field_by_id(totp).unwrap().modified_at, 1_500);
    assert_eq!(
        after.field_by_id(url).unwrap().modified_at,
        1_000,
        "untouched"
    );
    assert!(after.field_by_id(notes).is_none());
    assert_eq!(
        after.removed_fields,
        vec![FieldTombstone {
            id: notes,
            removed_at: 2_000
        }]
    );
    let pin = after.field("pin").unwrap().id;
    assert_eq!(after.field_by_id(pin).unwrap().modified_at, 2_000);
    assert_eq!(after.fields.len(), 5);
    assert_eq!(after.modified_at, 2_000);

    // Changing a field's id is a removal plus an addition.
    let fresh = Uuid::from_u128(0x5555);
    v.update(id, 3_000, |i| {
        i.fields.iter_mut().find(|f| f.id == url).unwrap().id = fresh;
    })
    .unwrap();
    let after = v.get(id).unwrap();
    assert!(after.field_by_id(url).is_none());
    assert_eq!(
        after.field_by_id(fresh).unwrap().modified_at,
        2_001,
        "new field with a carried stamp: stamp(carried 2000, item 2000)"
    );
    assert_eq!(after.removed_fields.len(), 2);
    assert_eq!(
        after.removed_fields[0],
        FieldTombstone {
            id: url,
            removed_at: 3_000
        }
    );

    // Removing a field whose own stamp is ahead of the item lifts the marker to it.
    v.update(id, 4_000, |i| {
        i.fields
            .iter_mut()
            .find(|f| f.id == pin)
            .unwrap()
            .modified_at = 9_000;
    })
    .unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, 9_000);
    v.update(id, 4_500, |i| i.fields.retain(|f| f.id != pin))
        .unwrap();
    let after = v.get(id).unwrap();
    assert_eq!(
        after.removed_fields[0],
        FieldTombstone {
            id: pin,
            removed_at: 9_001
        }
    );
    assert_eq!(after.modified_at, 9_001);

    // Re-adding a removed field by id (undo): it wins, stamped past the marker, marker gone.
    v.update(id, 4_600, |i| {
        let mut back = Field::new("notes", FieldKind::Notes, secret("back"), 0);
        back.id = notes;
        i.fields.push(back);
    })
    .unwrap();
    let after = v.get(id).unwrap();
    assert!(after.removed_fields.iter().all(|t| t.id != notes));
    assert_eq!(
        after.field_by_id(notes).unwrap().modified_at,
        9_002,
        "stamp(4600, prev item 9001)"
    );
    // ... and a re-add with an explicit stamp behind the marker is lifted past the marker.
    v.update(id, 4_700, |i| {
        let mut back = Field::new("url", FieldKind::Url, secret("https://x"), 1);
        back.id = url;
        i.fields.push(back);
    })
    .unwrap();
    let after = v.get(id).unwrap();
    assert_eq!(
        after.field_by_id(url).unwrap().modified_at,
        9_003,
        "stamp(carried 1 -> 9003)"
    );
    assert!(after.removed_fields.iter().all(|t| t.id != url));

    // Duplicate ids are refused and the item restored.
    let snapshot = v.get(id).unwrap().clone();
    let err = v
        .update(id, 5_000, |i| {
            let twin = i.fields[0].clone();
            i.fields.push(twin);
        })
        .unwrap_err();
    assert!(
        matches!(&err, VaultError::Malformed(m) if m.contains("duplicate field id")),
        "{err:?}"
    );
    assert!(item_eq(&snapshot, v.get(id).unwrap()), "restored");
    let mut dup = Item::new("dup", device(), 1);
    let f = Field::new("a", FieldKind::Text, secret("x"), 1);
    dup.fields.push(f.clone());
    dup.fields.push(f);
    assert!(matches!(
        v.try_insert(dup, 1).unwrap_err(),
        VaultError::Malformed(_)
    ));
}

#[test]
fn remove_field_restamps_and_lifts_to_the_field_stamp() {
    let mut v = new_vault();
    let id = v.insert(sample_item(6, 1_000), 1_000);
    let notes = fid(&v, id, "notes");
    // Clock behind: strictly advances.
    v.remove_field(id, notes, 500).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(
        item.removed_fields[0],
        FieldTombstone {
            id: notes,
            removed_at: 1_001
        }
    );
    assert_eq!(item.modified_at, 1_001);
    assert_eq!(item.device_id, device());
    assert_eq!(item.fields.len(), 4);
    // Twice: FieldNotFound, nothing changes.
    assert_eq!(
        v.remove_field(id, notes, 2_000).unwrap_err(),
        VaultError::FieldNotFound
    );
    assert_eq!(v.get(id).unwrap().modified_at, 1_001);
    // Field stamped ahead of the item (explicit future stamp): marker covers it.
    let url = fid(&v, id, "url");
    v.update(id, 1_500, |i| {
        i.fields
            .iter_mut()
            .find(|f| f.id == url)
            .unwrap()
            .modified_at = 8_000;
    })
    .unwrap();
    v.remove_field(id, url, 1_600).unwrap();
    assert_eq!(
        v.get(id).unwrap().removed_fields[0],
        FieldTombstone {
            id: url,
            removed_at: 8_001
        }
    );
    // Round trip keeps markers and the missing fields.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
}

#[test]
fn set_field_named_ambiguity_not_found_and_case() {
    let mut v = new_vault();
    let mut item = Item::new("Names", device(), 10);
    item.fields = vec![
        Field::new("password", FieldKind::Section, secret(""), 10),
        Field::new("Username", FieldKind::Text, secret("a"), 10),
        Field::new("USERNAME", FieldKind::Text, secret("b"), 10),
        Field::new("Password", FieldKind::Password, secret("pw"), 10),
        Field::new("", FieldKind::Text, secret("unnamed"), 10),
    ];
    let id = v.insert(item, 10);
    assert_eq!(
        v.set_field_named(id, "username", secret("x"), 20)
            .unwrap_err(),
        VaultError::AmbiguousField
    );
    assert_eq!(
        v.set_field_named(id, "nope", secret("x"), 20).unwrap_err(),
        VaultError::FieldNotFound
    );
    assert_eq!(
        v.set_field_named(id, "", secret("x"), 20).unwrap_err(),
        VaultError::FieldNotFound,
        "an empty name matches nothing, not even the unnamed field"
    );
    assert_eq!(v.get(id).unwrap().modified_at, 10, "errors change nothing");
    // One non-section match, case-insensitively; the section named `password` is skipped.
    v.set_field_named(id, "PASSWORD", secret("pw2"), 20)
        .unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(item.fields[3].value.expose_secret(), "pw2");
    assert_eq!(
        item.fields[0].value.expose_secret(),
        "",
        "section untouched"
    );
    assert_eq!(item.history.len(), 1);
    assert_eq!(item.history[0].field_id, Some(item.fields[3].id));
    // By id anything can be set, including the unnamed field and the section.
    let unnamed = item.fields[4].id;
    let heading = item.fields[0].id;
    v.set_field(id, unnamed, secret("named by id"), 30).unwrap();
    v.set_field(id, heading, secret("h"), 31).unwrap();
    assert_eq!(value(&v, id, unnamed), "named by id");
    assert_eq!(value(&v, id, heading), "h");
    assert_eq!(
        v.get(id).unwrap().history.len(),
        1,
        "no history for text or section"
    );
    // Unknown item still reports Malformed("unknown item ..") first.
    assert!(matches!(
        v.set_field_named(Uuid::nil(), "x", secret("x"), 1)
            .unwrap_err(),
        VaultError::Malformed(_)
    ));
}

// -------------------------------------------------------------------------------------------
// history field_id
// -------------------------------------------------------------------------------------------

#[test]
fn history_carries_field_id_and_its_on_disk_shape() {
    let mut v = new_vault();
    let id = v.insert(sample_item(7, 1_000), 1_000);
    let password = fid(&v, id, "password");
    v.set_field(id, password, secret("pw-2"), 2_000).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(item.history.len(), 2, "set_field entry + the sample entry");
    assert_eq!(item.history[0].field_id, Some(password));
    assert_eq!(item.history[1].field_id, None, "pushed without one");

    let entries = plain_map(item);
    let Some(Value::Array(hist)) = key(&entries, "history") else {
        panic!("history array")
    };
    assert_eq!(
        hist[0],
        Value::Map(vec![
            (t("value"), t("p\u{e4}ss-7-hunter2")),
            (t("field_id"), Value::Bytes(password.as_bytes().to_vec())),
            (t("replaced_at"), Value::Integer(2_000.into())),
        ]),
        "field_id is bytes(16), canonical position"
    );
    let Value::Map(second) = &hist[1] else {
        panic!()
    };
    assert!(
        !second.iter().any(|(k, _)| k == &t("field_id")),
        "None: key absent"
    );

    // Round trip; null / missing read as None; a bad value is Malformed.
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
    let edit_entry = |e: &mut Entries, idx: usize, f: &dyn Fn(&mut Entries)| {
        let Some((_, Value::Array(h))) = e.iter_mut().find(|(k, _)| k == &t("history")) else {
            panic!()
        };
        let Value::Map(m) = &mut h[idx] else { panic!() };
        f(m);
    };
    let null = reencode(item, FORMAT_VERSION, |e| {
        edit_entry(e, 0, &|m| set_key(m, "field_id", Value::Null))
    })
    .unwrap();
    assert_eq!(null.history[0].field_id, None);
    let missing = reencode(item, FORMAT_VERSION, |e| {
        edit_entry(e, 0, &|m| del_key(m, "field_id"))
    })
    .unwrap();
    assert_eq!(missing.history[0].field_id, None);
    for bad in [t("x"), Value::Bytes(vec![1; 8]), Value::Integer(1.into())] {
        let r = reencode(item, FORMAT_VERSION, |e| {
            edit_entry(e, 0, &|m| set_key(m, "field_id", bad.clone()))
        });
        assert!(matches!(r, Err(VaultError::Malformed(_))));
    }

    // Union: a v1-style twin (same value and stamp, no id) dedupes to the entry with the id.
    v.update(id, 2_000, |i| {
        i.history.push(HistoryEntry {
            value: secret("p\u{e4}ss-7-hunter2"),
            replaced_at: 2_000,
            field_id: None,
        });
    })
    .unwrap();
    assert_eq!(
        v.get(id).unwrap().history.len(),
        3,
        "update does not dedupe"
    );
    let (mut a, mut b) = (
        unlock(&v.serialize()).unwrap(),
        unlock(&v.serialize()).unwrap(),
    );
    a.set_device_id(dev_a());
    b.set_device_id(dev_b());
    converge(&mut a, &mut b);
    let h = &a.get(id).unwrap().history;
    assert_eq!(h.len(), 2, "merge dedupes on (value, replaced_at)");
    assert_eq!(
        h[0].field_id,
        Some(password),
        "the id-carrying twin survives"
    );

    // A conflict loser records the field id too.
    let (mut a, mut b, id) = two_devices();
    let password = fid(&a, id, "password");
    a.set_field(id, password, secret("from-A"), 5_000).unwrap();
    b.set_field(id, password, secret("from-B"), 6_000).unwrap();
    converge(&mut a, &mut b);
    let lost = a
        .get(id)
        .unwrap()
        .history
        .iter()
        .find(|h| h.value.expose_secret() == "from-A")
        .unwrap();
    assert_eq!(lost.replaced_at, 5_000);
    assert_eq!(lost.field_id, Some(password));
}
