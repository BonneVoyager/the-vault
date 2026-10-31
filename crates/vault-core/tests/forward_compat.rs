//! Forward compatibility (01 §9): an older build must open a newer file that only *added*
//! things — unknown map keys (already covered in roundtrip.rs) and unknown enum strings for
//! `slot.kind` and `field.kind` (covered here). Genuinely malformed data (wrong CBOR types,
//! missing required keys, bad lengths) must still be rejected.
//!
//! `item.kind` was removed on 2026-10-30: it is now an ordinary unknown key, so whatever an
//! older (or newer) file holds there lands in `Item::extras` and is written back verbatim.

mod common;

use ciborium::Value;
use common::*;
use vault_core::format::{self, VaultFile};
use vault_core::search::{Query, search};
use vault_core::{
    ExposeSecret, FORMAT_VERSION, Field, FieldKind, Item, LockedVault, OpaqueSlot, SecretVec, Slot,
    SlotKind, TamperKind, Uuid, VaultError, export_csv, merge,
};

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn opaque(id: u128) -> OpaqueSlot {
    OpaqueSlot::new(
        Uuid::from_u128(id),
        "future-kind",
        vec![(t("payload"), Value::Bytes(vec![7; 12]))],
    )
    .unwrap()
}

/// A populated vault whose header has an opaque slot *before* its password slot.
fn with_opaque_first() -> (Vec<u8>, Uuid) {
    let mut v = unstamped_vault();
    populate(&mut v, 2);
    let bytes = rewrite(&v.serialize(), |f| {
        f.header.slots.insert(0, Slot::Opaque(opaque(0x55)));
    });
    (bytes, Uuid::from_u128(0x55))
}

#[test]
fn opaque_slot_is_skipped_on_unlock_and_preserved_in_position() {
    let (bytes, opaque_id) = with_opaque_first();
    let locked = LockedVault::parse(&bytes).unwrap();
    let kinds: Vec<_> = locked.slots().collect();
    assert_eq!(kinds.len(), 2);
    assert_eq!(kinds[0], (opaque_id, SlotKind::Other("future-kind".into())));
    assert_eq!(kinds[1].1, SlotKind::Password);
    assert_eq!(locked.item_summaries().count(), 2);

    let vault = locked.unlock(&pw()).unwrap();
    assert_eq!(vault.slots().collect::<Vec<_>>(), kinds);
    let out = vault.serialize();
    let file = VaultFile::parse(&out).unwrap();
    assert_eq!(file.header.slots[0], Slot::Opaque(opaque(0x55)));
    assert!(file.header.slots[1].is_key_of(SlotKind::Password));
    assert_vaults_eq(&vault, &unlock(&out).unwrap());

    // Wrong password with an opaque slot present is still WrongPassword (a password slot
    // exists), not NoUsableSlot.
    assert_eq!(
        LockedVault::parse(&bytes)
            .unwrap()
            .unlock(&secret("nope"))
            .unwrap_err(),
        VaultError::WrongPassword
    );
}

#[test]
fn no_password_slot_is_no_usable_slot() {
    let mut v = new_vault();
    populate(&mut v, 1);
    let kek = SecretVec::new(vec![3u8; 32]);
    let enclave = v.add_enclave_slot(&kek, 5_000);
    let bytes = v.serialize();

    // Only an opaque slot left: this build cannot unlock it with a password.
    let only_opaque = rewrite(&bytes, |f| {
        f.header.slots = vec![Slot::Opaque(opaque(0x66))];
    });
    let locked = LockedVault::parse(&only_opaque).unwrap();
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::NoUsableSlot);
    // ... and pointing unlock_with_kek at the opaque slot is NoUsableSlot too, while an
    // unknown id is still Malformed.
    assert_eq!(
        locked
            .unlock_with_kek(Uuid::from_u128(0x66), &kek)
            .unwrap_err(),
        VaultError::NoUsableSlot
    );
    assert!(matches!(
        locked.unlock_with_kek(enclave, &kek).unwrap_err(),
        VaultError::Malformed(_)
    ));

    // Only an enclave slot: same error for a password unlock, decided from the plaintext
    // before any key work. The enclave KEK unwraps its slot, but the file is stamped
    // (`add_enclave_slot`) and the slot set is digest-bound into the manifest (01 §4), so
    // removing the password slot by hand is caught as Tampered(Manifest).
    let only_enclave = rewrite(&bytes, |f| {
        f.header.slots.retain(|s| s.is_key_of(SlotKind::Enclave));
    });
    let locked = LockedVault::parse(&only_enclave).unwrap();
    assert_eq!(locked.unlock(&pw()).unwrap_err(), VaultError::NoUsableSlot);
    assert_eq!(
        locked.unlock_with_kek(enclave, &kek).unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn opaque_slot_can_be_removed_and_is_dropped_by_rotation() {
    let (bytes, opaque_id) = with_opaque_first();

    let mut v = unlock(&bytes).unwrap();
    v.remove_slot(opaque_id, 5_000).unwrap();
    assert_eq!(v.slots().count(), 1);
    assert!(v.slots().all(|(_, k)| k == SlotKind::Password));
    assert!(matches!(
        v.remove_slot(opaque_id, 5_001).unwrap_err(),
        VaultError::Malformed(_)
    ));

    let mut v = unlock(&bytes).unwrap();
    v.rotate_vault_key(&pw(), 5_000).unwrap();
    assert_eq!(v.slots().count(), 1, "opaque slot dropped by rotation");
    assert!(v.slots().all(|(_, k)| k == SlotKind::Password));
    let reopened = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &reopened);
}

#[test]
fn unknown_field_kinds_roundtrip_merge_search_and_export() {
    let mut v = new_vault();
    populate(&mut v, 1);
    let mut item = Item::new("Hover car", device(), 10);
    let mut licence = Field::new("licence", FieldKind::Other, secret("XYZ-123"), 10);
    licence.kind_raw = Some("future-field-kind".into());
    item.fields.push(licence);
    item.fields.push(Field::new(
        "password",
        FieldKind::Password,
        secret("pw"),
        10,
    ));
    let id = v.insert(item, 10);

    let reopened = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &reopened);
    let got = reopened.get(id).unwrap();
    assert_eq!(got.fields[0].kind, FieldKind::Other);
    assert_eq!(got.fields[0].kind_str(), "future-field-kind");
    assert!(reopened.items().any(|i| i.id == id), "items() includes it");

    // Merge treats it like any other item.
    let mut other = new_vault();
    let theirs = unlock(&v.serialize()).unwrap();
    // `other` is a different vault_id; merge requires the same, so merge into a copy of a
    // vault that lacks the item instead.
    let mut mine = unlock(&v.serialize()).unwrap();
    mine.delete(id, 20).unwrap();
    mine.purge_tombstones_older_than(u64::MAX);
    assert!(mine.get(id).is_none());
    let report = mine.merge_from(&theirs).unwrap();
    assert_eq!(report.added, 1);
    assert!(merge::item_eq(
        mine.get(id).unwrap(),
        theirs.get(id).unwrap()
    ));
    other.purge_tombstones_older_than(0);

    // Search by title works.
    let q = Query {
        text: "hover",
        tag: None,
        favorites_only: false,
    };
    assert_eq!(search(&reopened, &q).len(), 1);

    // CSV export includes the item: title and password, but not the unknown-kind field.
    let csv = export_csv(&reopened);
    let text = String::from_utf8(csv.0.clone()).unwrap();
    assert!(text.contains("Hover car"));
    assert!(!text.contains("XYZ-123"), "unknown field is not exported");

    // An `Other` field built without `kind_raw` serializes as the "other" placeholder and
    // comes back as Other with kind_raw = Some("other").
    let mut bare = Item::new("Bare", device(), 40);
    bare.fields
        .push(Field::new("f", FieldKind::Other, secret("x"), 40));
    let bare_id = v.insert(bare, 40);
    let again = unlock(&v.serialize()).unwrap();
    let b = again.get(bare_id).unwrap();
    assert_eq!(b.fields[0].kind, FieldKind::Other);
    assert_eq!(b.fields[0].kind_raw.as_deref(), Some("other"));

    // set_field on an unknown-kind field behaves like text: no history entry.
    let mut v = reopened;
    v.set_field_named(id, "licence", secret("NEW-1"), 30)
        .unwrap();
    let got = v.get(id).unwrap();
    assert_eq!(got.fields[0].value.expose_secret(), "NEW-1");
    assert!(got.history.is_empty());
    v.set_field_named(id, "password", secret("pw2"), 31)
        .unwrap();
    assert_eq!(v.get(id).unwrap().history.len(), 1);
}

#[test]
fn malformed_field_kinds_are_still_rejected_and_item_kind_is_just_an_extra() {
    // `kind` on the item is a plain unknown key since 2026-10-30: any value (or none) is
    // accepted and preserved. `kind` on a field is still required text.
    let base = |kind: Option<Value>, field_kind: Option<Value>| -> Vec<u8> {
        let mut field = vec![
            (t("name"), t("f")),
            (t("value"), t("v")),
            (t("modified_at"), Value::Integer(1.into())),
            (t("section"), Value::Null),
        ];
        if let Some(fk) = field_kind {
            field.push((t("kind"), fk));
        }
        let mut plain = vec![
            (t("title"), t("x")),
            (t("deleted_at"), Value::Null),
            (t("device_id"), Value::Bytes(vec![0; 16])),
            (t("favorite"), Value::Bool(false)),
            (t("tags"), Value::Array(vec![])),
            (t("fields"), Value::Array(vec![Value::Map(field)])),
            (t("history"), Value::Array(vec![])),
        ];
        if let Some(k) = kind {
            plain.insert(0, (t("kind"), k));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(plain), &mut out).unwrap();
        out
    };
    let decode = |b: &[u8]| format::decode_item_plain(b, Uuid::nil(), 1, 1);

    // Unknown field kind strings are fine; the item's `kind` string lands in extras.
    let item = decode(&base(
        Some(t("future-item-kind")),
        Some(t("future-field-kind")),
    ))
    .unwrap();
    assert_eq!(item.extras, vec![(t("kind"), t("future-item-kind"))]);
    assert_eq!(item.fields[0].kind, FieldKind::Other);
    assert_eq!(
        item.fields[0].kind_raw.as_deref(),
        Some("future-field-kind")
    );
    // A formerly known item kind is preserved the same way; the removed "number" field kind
    // and the "other" placeholder are unknown field kinds.
    let item = decode(&base(Some(t("login")), Some(t("number")))).unwrap();
    assert_eq!(item.extras, vec![(t("kind"), t("login"))]);
    assert_eq!(item.fields[0].kind, FieldKind::Other);
    assert_eq!(item.fields[0].kind_raw.as_deref(), Some("number"));
    let item = decode(&base(Some(t("login")), Some(t("other")))).unwrap();
    assert_eq!(item.fields[0].kind_raw.as_deref(), Some("other"));
    // No item kind at all, or a non-text one, is accepted (and the latter preserved).
    let item = decode(&base(None, Some(t("text")))).unwrap();
    assert!(item.extras.is_empty());
    let item = decode(&base(Some(Value::Integer(1.into())), Some(t("text")))).unwrap();
    assert_eq!(item.extras, vec![(t("kind"), Value::Integer(1.into()))]);
    // A wrong-typed or missing field kind is still structural damage.
    assert!(matches!(
        decode(&base(None, Some(Value::Bytes(vec![1])))).unwrap_err(),
        VaultError::Malformed(_)
    ));
    assert!(matches!(
        decode(&base(None, None)).unwrap_err(),
        VaultError::Malformed(_)
    ));
}

/// An `ItemPlain` written by a pre-2026-10-30 build (with `"kind"`) decodes and re-encodes to
/// exactly the same bytes: the key survives in `extras` and is sorted back into canonical
/// position by the writer. A freshly built item never gains a `kind` key.
#[test]
fn legacy_item_kind_round_trips_byte_identically_and_is_never_written() {
    let mut v = new_vault();
    populate(&mut v, 1);
    let item = v.items().next().unwrap();
    let plain = format::encode_item_plain(item);
    let decoded: Value = ciborium::from_reader(plain.as_slice()).unwrap();
    let Value::Map(entries) = decoded else {
        panic!()
    };
    assert!(
        entries.iter().all(|(k, _)| k != &t("kind")),
        "writer must not emit an item kind"
    );

    // Build the legacy layout: the same map plus `kind`, in canonical order (shortest encoded
    // key first, then bytewise), exactly where the old writer put it.
    for raw in ["login", "note", "card", "identity", "future-item-kind", ""] {
        let mut legacy = entries.clone();
        legacy.push((t("kind"), t(raw)));
        legacy.sort_by_key(|(k, _)| {
            let mut enc = Vec::new();
            ciborium::into_writer(k, &mut enc).unwrap();
            enc
        });
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(legacy), &mut bytes).unwrap();

        let got =
            format::decode_item_plain(&bytes, item.id, item.modified_at, FORMAT_VERSION).unwrap();
        assert_eq!(got.extras, vec![(t("kind"), t(raw))], "{raw:?}");
        assert_eq!(got.title, item.title);
        assert_eq!(got.tags, item.tags, "{raw:?}: tags untouched");
        assert_eq!(
            format::encode_item_plain(&got).as_slice(),
            bytes.as_slice(),
            "{raw:?}: byte-identical re-encode"
        );
    }
}

#[test]
fn opaque_slot_constructor_rejects_known_kinds_and_reserved_keys() {
    for kind in ["password", "enclave", "recovery"] {
        assert!(matches!(
            OpaqueSlot::new(Uuid::from_u128(1), kind, vec![]).unwrap_err(),
            VaultError::Malformed(_)
        ));
    }
    assert!(matches!(
        OpaqueSlot::new(Uuid::from_u128(1), "x", vec![(t("id"), Value::Null)]).unwrap_err(),
        VaultError::Malformed(_)
    ));
    assert!(matches!(
        OpaqueSlot::new(Uuid::from_u128(1), "x", vec![(t("kind"), Value::Null)]).unwrap_err(),
        VaultError::Malformed(_)
    ));
    let ok = OpaqueSlot::new(Uuid::from_u128(1), "Password", vec![]).unwrap();
    assert_eq!(ok.kind(), "Password", "case matters: not a known kind");
    assert_eq!(ok.id(), Uuid::from_u128(1));
    assert!(ok.extras().is_empty());
}

#[test]
fn duplicate_slot_ids_are_malformed() {
    let mut v = new_vault();
    let kek = SecretVec::new(vec![9u8; 32]);
    let enclave = v.add_enclave_slot(&kek, 5_000);
    let bytes = v.serialize();

    // Opaque slot shadowing the enclave slot's id, inserted ahead of it.
    let shadowed = rewrite(&bytes, |f| {
        let dup = OpaqueSlot::new(enclave, "future-kind", vec![]).unwrap();
        f.header.slots.insert(0, Slot::Opaque(dup));
    });
    assert!(matches!(
        LockedVault::parse(&shadowed).unwrap_err(),
        VaultError::Malformed(_)
    ));
    // Two key slots with the same id.
    let twin = rewrite(&bytes, |f| {
        let copy = f.header.slots[0].clone();
        f.header.slots.push(copy);
    });
    assert!(matches!(
        LockedVault::parse(&twin).unwrap_err(),
        VaultError::Malformed(_)
    ));
    // Distinct ids are fine, and the enclave slot is still found by id with an opaque slot
    // ahead of it. The opaque slot is spliced into the *unstamped* file before the enclave
    // slot is added, so the stamped header's digest covers it (splicing it into the stamped
    // file would be a tamper, 01 §4).
    let v = unstamped_vault();
    let with_opaque = rewrite(&v.serialize(), |f| {
        f.header.slots.insert(0, Slot::Opaque(opaque(0x77)));
    });
    let mut v = unlock(&with_opaque).unwrap();
    let enclave = v.add_enclave_slot(&kek, 5_000);
    let locked = LockedVault::parse(&v.serialize()).unwrap();
    assert_eq!(locked.header().slots[0], Slot::Opaque(opaque(0x77)));
    assert!(locked.unlock_with_kek(enclave, &kek).is_ok());
    let spliced = rewrite(&v.serialize(), |f| {
        f.header.slots.insert(0, Slot::Opaque(opaque(0x78)));
    });
    assert_eq!(
        LockedVault::parse(&spliced)
            .unwrap()
            .unlock_with_kek(enclave, &kek)
            .unwrap_err(),
        VaultError::Tampered(TamperKind::Manifest)
    );
}

#[test]
fn unknown_kind_strings_are_exact_matches_only() {
    // Empty, capitalised and trailing-space strings are all unknown.
    let v = unlock(&{
        let mut v = new_vault();
        populate(&mut v, 1);
        v.serialize()
    })
    .unwrap();
    let item = v.items().next().unwrap();
    let plain = format::encode_item_plain(item);
    let field = |raw: &str| -> Vec<u8> {
        let mut val: Value = ciborium::from_reader(plain.as_slice()).unwrap();
        let Value::Map(entries) = &mut val else {
            panic!()
        };
        let fields = entries.iter_mut().find(|(k, _)| k == &t("fields")).unwrap();
        let Value::Array(fields) = &mut fields.1 else {
            panic!()
        };
        let Value::Map(first) = &mut fields[0] else {
            panic!()
        };
        for (k, vv) in first.iter_mut() {
            if k == &t("kind") {
                *vv = t(raw);
            }
        }
        let mut out = Vec::new();
        ciborium::into_writer(&val, &mut out).unwrap();
        out
    };
    for raw in ["", "Text", "text ", "number"] {
        let got = format::decode_item_plain(&field(raw), item.id, 1, FORMAT_VERSION).unwrap();
        assert_eq!(got.fields[0].kind, FieldKind::Other, "{raw:?}");
        assert_eq!(got.fields[0].kind_raw.as_deref(), Some(raw));
        assert_eq!(got.fields[0].kind_str(), raw);
    }
    for raw in ["", "Password", "password ", "number"] {
        assert_eq!(FieldKind::parse(raw), None, "{raw:?}");
        assert_eq!(SlotKind::from_raw(raw), SlotKind::Other(raw.to_owned()));
    }
}

#[test]
fn opaque_slots_survive_slot_management_and_keep_order() {
    // Spliced into an unstamped file: a fresh vault is stamped and digest-bound (01 §4).
    let mut v = unstamped_vault();
    populate(&mut v, 1);
    let nested = OpaqueSlot::new(
        Uuid::from_u128(0xA1),
        "future-kind",
        vec![(
            t("nested"),
            Value::Map(vec![
                (
                    t("inner"),
                    Value::Array(vec![Value::Integer(1.into()), t("two")]),
                ),
                (
                    t("deep"),
                    Value::Map(vec![(t("k"), Value::Bytes(vec![1, 2, 3]))]),
                ),
            ]),
        )],
    )
    .unwrap();
    let second = OpaqueSlot::new(Uuid::from_u128(0xA2), "another-future-kind", vec![]).unwrap();
    let bytes = rewrite(&v.serialize(), |f| {
        f.header.slots.insert(0, Slot::Opaque(nested.clone()));
        f.header.slots.push(Slot::Opaque(second.clone()));
    });
    // Nested-map extra round-trips (keys come back canonically sorted inside the map).
    let expect_nested = OpaqueSlot::new(
        Uuid::from_u128(0xA1),
        "future-kind",
        vec![(
            t("nested"),
            Value::Map(vec![
                (
                    t("deep"),
                    Value::Map(vec![(t("k"), Value::Bytes(vec![1, 2, 3]))]),
                ),
                (
                    t("inner"),
                    Value::Array(vec![Value::Integer(1.into()), t("two")]),
                ),
            ]),
        )],
    )
    .unwrap();
    let kinds = |v: &vault_core::UnlockedVault| v.slots().map(|(_, k)| k).collect::<Vec<_>>();
    let other = |s: &str| SlotKind::Other(s.to_owned());

    let mut v = unlock(&bytes).unwrap();
    assert_eq!(
        kinds(&v),
        [
            other("future-kind"),
            SlotKind::Password,
            other("another-future-kind")
        ]
    );
    let kek = SecretVec::new(vec![4u8; 32]);
    let enclave = v.add_enclave_slot(&kek, 5_000);
    assert_eq!(
        kinds(&v),
        [
            other("future-kind"),
            SlotKind::Password,
            other("another-future-kind"),
            SlotKind::Enclave
        ]
    );
    v.remove_slot(enclave, 5_001).unwrap();
    assert_eq!(
        kinds(&v),
        [
            other("future-kind"),
            SlotKind::Password,
            other("another-future-kind")
        ]
    );

    let out = v.serialize();
    let file = VaultFile::parse(&out).unwrap();
    assert_eq!(file.header.slots[0], Slot::Opaque(expect_nested));
    assert!(file.header.slots[1].is_key_of(SlotKind::Password));
    assert_eq!(file.header.slots[2], Slot::Opaque(second));
    assert_eq!(
        file.to_bytes(),
        out,
        "canonical re-encode is byte-identical"
    );
    assert!(unlock(&out).is_ok());
}
