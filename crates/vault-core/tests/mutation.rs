//! `update`, `set_field`, `delete`, `purge_tombstones_older_than` (02 "write").

mod common;

use common::*;
use vault_core::vault::HISTORY_CAP;
use vault_core::{ExposeSecret, Field, FieldKind, Item, Uuid, VaultError};

fn vault_with_item(now: u64) -> (vault_core::UnlockedVault, Uuid) {
    let mut v = new_vault();
    let id = v.insert(sample_item(1, now), now);
    (v, id)
}

#[test]
fn update_bumps_changed_field_without_timestamp_and_item() {
    let (mut v, id) = vault_with_item(1_000);
    let before = v.get(id).unwrap().clone();
    assert_eq!(before.field("password").unwrap().modified_at, 999);

    v.update(id, 5_000, |item| {
        // Change the value but "forget" the timestamp.
        let f = item
            .fields
            .iter_mut()
            .find(|f| f.name == "username")
            .unwrap();
        f.value = secret("renamed@example.com");
        item.title = "New title".into();
    })
    .unwrap();

    let after = v.get(id).unwrap();
    assert_eq!(after.title, "New title");
    assert_eq!(after.modified_at, 5_000);
    assert_eq!(after.device_id, device());
    assert_eq!(after.field("username").unwrap().modified_at, 5_000);
    assert_eq!(
        after.field("username").unwrap().value.expose_secret(),
        "renamed@example.com"
    );
    for name in ["password", "totp", "url", "notes"] {
        assert_eq!(
            after.field(name).unwrap().modified_at,
            before.field(name).unwrap().modified_at,
            "untouched field {name} keeps its timestamp"
        );
    }
}

#[test]
fn update_detects_kind_and_section_changes_and_respects_explicit_timestamps() {
    let (mut v, id) = vault_with_item(1_000);
    v.update(id, 2_000, |item| {
        item.fields[0].kind = FieldKind::Email; // username, content change
        item.fields[3].section = None; // url, content change
        // notes: value change with an explicit timestamp -> kept
        item.fields[4].value = secret("other notes");
        item.fields[4].modified_at = 1_500;
    })
    .unwrap();
    let after = v.get(id).unwrap();
    assert_eq!(after.field("username").unwrap().modified_at, 2_000);
    assert_eq!(after.field("url").unwrap().modified_at, 2_000);
    assert_eq!(after.field("notes").unwrap().modified_at, 1_500);
    assert_eq!(after.modified_at, 2_000);
}

#[test]
fn update_new_fields_and_metadata_only() {
    let (mut v, id) = vault_with_item(1_000);
    // Metadata-only edit still moves the item to `now`.
    v.update(id, 3_000, |item| item.favorite = !item.favorite)
        .unwrap();
    assert_eq!(v.get(id).unwrap().modified_at, 3_000);

    v.update(id, 4_000, |item| {
        item.fields
            .push(Field::new("pin", FieldKind::Text, secret("1234"), 0));
        item.fields
            .push(Field::new("note2", FieldKind::Notes, secret("x"), 3_500));
        // An explicit future timestamp on a field drags the item along.
        item.fields
            .push(Field::new("future", FieldKind::Text, secret("y"), 9_000));
    })
    .unwrap();
    let after = v.get(id).unwrap();
    assert_eq!(after.field("pin").unwrap().modified_at, 4_000, "0 -> now");
    assert_eq!(after.field("note2").unwrap().modified_at, 3_500, "kept");
    assert_eq!(after.modified_at, 9_000, "max over fields");

    // A `now` behind the item never rolls it back: the edit strictly advances modified_at
    // (previous + 1) so it still wins a merge against the untouched copy. The id cannot be
    // changed.
    v.update(id, 10, |item| {
        item.id = Uuid::nil();
        item.title = "again".into();
    })
    .unwrap();
    let after = v.get(id).unwrap();
    assert_eq!(after.id, id);
    assert_eq!(after.modified_at, 9_001);
    assert!(v.get(Uuid::nil()).is_none());
}

#[test]
fn unknown_ids_and_fields_are_errors() {
    let (mut v, id) = vault_with_item(1_000);
    let missing = Uuid::from_u128(42);
    assert!(matches!(
        v.update(missing, 1, |_| {}).unwrap_err(),
        VaultError::Malformed(m) if m.contains("unknown item")
    ));
    assert!(matches!(
        v.set_field(missing, "username", secret("x"), 1).unwrap_err(),
        VaultError::Malformed(m) if m.contains("unknown item")
    ));
    assert!(matches!(
        v.delete(missing, 1).unwrap_err(),
        VaultError::Malformed(_)
    ));
    assert!(matches!(
        v.set_field(id, "nope", secret("x"), 1).unwrap_err(),
        VaultError::Malformed(m) if m.contains("unknown field")
    ));
    assert!(v.get(id).unwrap().field("nope").is_none(), "not created");
    assert_eq!(v.get(id).unwrap().modified_at, 1_000, "nothing stamped");
}

#[test]
fn set_field_password_pushes_history_newest_first_capped() {
    let (mut v, id) = vault_with_item(1_000);
    assert!(v.get(id).unwrap().history.is_empty());

    v.set_field(id, "password", secret("pw-1"), 2_000).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(
        item.field("password").unwrap().value.expose_secret(),
        "pw-1"
    );
    assert_eq!(item.field("password").unwrap().modified_at, 2_000);
    assert_eq!(item.modified_at, 2_000);
    assert_eq!(item.history.len(), 1);
    assert_eq!(item.history[0].value.expose_secret(), "p\u{e4}ss-1-hunter2");
    assert_eq!(item.history[0].replaced_at, 2_000);

    for i in 2..=12u64 {
        v.set_field(id, "password", secret(format!("pw-{i}")), 2_000 + i)
            .unwrap();
    }
    let item = v.get(id).unwrap();
    assert_eq!(
        item.field("password").unwrap().value.expose_secret(),
        "pw-12"
    );
    assert_eq!(item.history.len(), HISTORY_CAP);
    assert_eq!(
        item.history[0].value.expose_secret(),
        "pw-11",
        "newest first"
    );
    assert_eq!(item.history[0].replaced_at, 2_012);
    assert_eq!(item.history[9].value.expose_secret(), "pw-2", "oldest kept");
    assert!(
        item.history
            .windows(2)
            .all(|w| w[0].replaced_at > w[1].replaced_at),
        "sorted by replaced_at desc"
    );
    assert_eq!(item.modified_at, 2_012);

    // Non-password fields do not touch history.
    v.set_field(id, "username", secret("u2"), 3_000).unwrap();
    let item = v.get(id).unwrap();
    assert_eq!(item.history.len(), HISTORY_CAP);
    assert_eq!(item.field("username").unwrap().modified_at, 3_000);
    assert_eq!(item.modified_at, 3_000);
}

#[test]
fn delete_tombstones_and_purge() {
    let mut v = new_vault();
    let a = v.insert(sample_item(1, 1_000), 1_000);
    let b = v.insert(sample_item(2, 1_000), 1_000);
    let c = v.insert(sample_item(3, 1_000), 1_000);

    v.delete(a, 2_000).unwrap();
    let dead = v.get(a).unwrap();
    assert_eq!(dead.deleted_at, Some(2_000));
    assert_eq!(dead.modified_at, 2_000);
    assert_eq!(dead.device_id, device());
    assert!(dead.is_deleted());
    assert_eq!(dead.fields.len(), 5, "fields kept");
    assert_eq!(v.items().count(), 2);
    assert!(v.items().all(|i| i.id != a));
    assert_eq!(v.items_including_deleted().count(), 3);

    // delete with a `now` behind modified_at: deleted_at and modified_at strictly advance
    // (previous + 1), so the tombstone still beats a peer's untouched copy.
    v.delete(b, 500).unwrap();
    assert_eq!(v.get(b).unwrap().deleted_at, Some(1_001));
    assert_eq!(v.get(b).unwrap().modified_at, 1_001);

    assert_eq!(
        v.purge_tombstones_older_than(1_001),
        0,
        "strictly older only"
    );
    assert_eq!(v.purge_tombstones_older_than(1_002), 1);
    assert!(v.get(b).is_none());
    assert!(v.get(a).is_some());
    assert!(v.get(c).is_some());
    assert_eq!(v.purge_tombstones_older_than(u64::MAX), 1);
    assert_eq!(v.items_including_deleted().count(), 1);
    assert_eq!(v.items().next().unwrap().id, c);

    // Round-trip of a vault with a tombstone that still carries fields.
    let d = v.insert(Item::new("n", Uuid::nil(), 1), 1);
    v.delete(d, 2).unwrap();
    let u = unlock(&v.serialize()).unwrap();
    assert_vaults_eq(&v, &u);
}
