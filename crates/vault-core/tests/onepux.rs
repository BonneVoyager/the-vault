//! 1PUX import (`import_1pux`).

use std::io::Write;

use serde_json::{Value, json};
use vault_core::import::{ImportError, import_1pux};
use vault_core::{ExposeSecret, FieldKind, Item, Uuid};

const NOW: u64 = 1_700_000_000_000;

fn zip_with(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, data) in files {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn archive(data: &Value) -> Vec<u8> {
    zip_with(&[
        ("export.attributes", b"{}"),
        ("export.data", data.to_string().as_bytes()),
    ])
}

fn export(items: Vec<Value>) -> Value {
    json!({"accounts": [{"vaults": [{"attrs": {}, "items": items}]}]})
}

fn val(item: &Item, name: &str) -> String {
    item.field(name)
        .unwrap_or_else(|| panic!("missing field {name}"))
        .value
        .expose_secret()
        .clone()
}

fn sample() -> Value {
    let history: Vec<Value> = (1..=12)
        .map(|i| json!({"value": format!("old{i}"), "time": 1000 + i}))
        .collect();
    export(vec![
        json!({
            "uuid": "a", "favIndex": 1, "createdAt": 1, "updatedAt": 2, "state": "active",
            "categoryUuid": "001",
            "details": {
                "loginFields": [
                    {"value": "alice", "name": "u", "fieldType": "T", "designation": "username"},
                    {"value": "s3cret", "name": "p", "fieldType": "P", "designation": "password"}
                ],
                "notesPlain": "some notes",
                "sections": [{"title": "Extra", "fields": [
                    {"title": "one-time", "id": "t", "value": {"totp": "otpauth://totp/x?secret=ABC"}},
                    {"title": "username", "id": "u2", "value": {"string": "dup"}},
                    {"title": "username", "id": "u3", "value": {"string": "dup2"}},
                    {"title": "since", "id": "d", "value": {"date": 1_700_000_000}},
                    {"title": "", "id": "fallback-id", "value": {"email": "a@b.c"}}
                ]}],
                "passwordHistory": history
            },
            "overview": {"title": "Example", "url": "https://example.com", "tags": ["work", "dev"],
                         "urls": [{"url": "https://example.com"}]}
        }),
        json!({"uuid": "b", "favIndex": 0, "state": "active", "categoryUuid": "003",
               "details": {"notesPlain": "note body"}, "overview": {"title": "My note"}}),
        json!({"uuid": "c", "state": "active", "categoryUuid": "002",
               "details": {"sections": [{"title": "", "fields": [
                   {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
                   {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202912}},
                   {"title": "verification number", "id": "cvv", "value": {"concealed": "123"}}
               ]}]},
               "overview": {"title": "Visa"}}),
        json!({"uuid": "d", "state": "active", "categoryUuid": "004",
               "details": {"sections": [{"title": "Name", "fields": [
                   {"title": "first name", "id": "fn", "value": {"string": "Alice"}}]}]},
               "overview": {"title": ""}}),
        json!({"uuid": "e", "state": "archived", "categoryUuid": "001",
               "details": {}, "overview": {"title": "Old"}}),
    ])
}

#[test]
fn imports_active_items() {
    let dev = Uuid::new_v4();
    let items = import_1pux(&archive(&sample()), dev, NOW).unwrap();
    assert_eq!(items.len(), 4);
    for it in &items {
        assert_eq!(it.modified_at, NOW);
        assert_eq!(it.device_id, dev);
        assert!(it.fields.iter().all(|f| f.modified_at == NOW));
    }
    let ids: std::collections::HashSet<_> = items.iter().map(|i| i.id).collect();
    assert_eq!(ids.len(), 4);
    // Categories map to template tags (item kinds were removed on 2026-10-30).
    assert_eq!(
        items.iter().map(|i| i.tags[0].as_str()).collect::<Vec<_>>(),
        ["login", "note", "card", "identity"]
    );
    assert!(items.iter().all(|i| i.title != "Old"));
    assert_eq!(items[3].title, "Untitled");
    // `createdAt` (seconds) becomes `created_at` (millis); an item without one gets `now`.
    assert_eq!(
        items.iter().map(|i| i.created_at).collect::<Vec<_>>(),
        [Some(1_000), Some(NOW), Some(NOW), Some(NOW)],
        "a carries createdAt: 1; b, c and d have none"
    );
}

#[test]
fn created_at_ignores_unusable_values() {
    let items = import_1pux(
        &archive(&export(vec![
            json!({"uuid": "z", "state": "active", "categoryUuid": "001", "createdAt": 0,
                   "details": {}, "overview": {"title": "Zero"}}),
            json!({"uuid": "s", "state": "active", "categoryUuid": "001", "createdAt": "1700000000",
                   "details": {}, "overview": {"title": "String"}}),
            json!({"uuid": "n", "state": "active", "categoryUuid": "001", "createdAt": -5,
                   "details": {}, "overview": {"title": "Negative"}}),
            json!({"uuid": "r", "state": "active", "categoryUuid": "001", "createdAt": 1_700_000_000,
                   "details": {}, "overview": {"title": "Real"}}),
        ])),
        Uuid::nil(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        items.iter().map(|i| i.created_at).collect::<Vec<_>>(),
        [Some(NOW), Some(NOW), Some(NOW), Some(1_700_000_000_000)],
        "zero, text and negative fall back to now; a real stamp is kept"
    );
}

#[test]
fn login_fields_tags_favorite_history() {
    let items = import_1pux(&archive(&sample()), Uuid::nil(), NOW).unwrap();
    let login = &items[0];
    assert_eq!(login.title, "Example");
    assert!(login.favorite);
    assert_eq!(login.tags, ["login", "work", "dev"]);
    assert_eq!(val(login, "username"), "alice");
    assert_eq!(login.field("username").unwrap().kind, FieldKind::Text);
    assert_eq!(val(login, "password"), "s3cret");
    assert_eq!(login.field("password").unwrap().kind, FieldKind::Password);
    assert_eq!(val(login, "url"), "https://example.com");
    assert_eq!(login.field("url").unwrap().kind, FieldKind::Url);
    assert_eq!(val(login, "notes"), "some notes");
    assert_eq!(login.field("notes").unwrap().kind, FieldKind::Notes);

    let totp = login.field("one-time").unwrap();
    assert_eq!(totp.kind, FieldKind::Totp);
    assert_eq!(totp.value.expose_secret(), "otpauth://totp/x?secret=ABC");
    assert_eq!(totp.section.as_deref(), Some("Extra"));
    assert_eq!(login.field("password").unwrap().section, None);

    // Name collisions get a suffix.
    assert_eq!(val(login, "username (2)"), "dup");
    assert_eq!(val(login, "username (3)"), "dup2");
    // Title empty falls back to id.
    assert_eq!(login.field("fallback-id").unwrap().kind, FieldKind::Email);
    // Dates.
    assert_eq!(val(login, "since"), "2023-11-14");
    assert_eq!(login.field("since").unwrap().kind, FieldKind::Date);

    // History: 12 entries capped to the 10 newest.
    assert_eq!(login.history.len(), 10);
    assert_eq!(login.history[0].value.expose_secret(), "old12");
    assert_eq!(login.history[0].replaced_at, 1012 * 1000);
    assert_eq!(login.history[9].value.expose_secret(), "old3");
    let mut names: Vec<_> = login.fields.iter().map(|f| f.name.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), login.fields.len());
}

#[test]
fn card_note_identity() {
    let items = import_1pux(&archive(&sample()), Uuid::nil(), NOW).unwrap();
    assert_eq!(val(&items[1], "notes"), "note body");
    assert!(!items[1].favorite);
    let card = &items[2];
    assert_eq!(val(card, "number"), "4111111111111111");
    assert_eq!(card.field("number").unwrap().kind, FieldKind::Text);
    let exp = card.field("expiry date").unwrap();
    assert_eq!(exp.kind, FieldKind::MonthYear);
    assert_eq!(exp.value.expose_secret(), "12/2029");
    let cvv = card.field("verification number").unwrap();
    assert_eq!(cvv.kind, FieldKind::Password);
    assert_eq!(cvv.value.expose_secret(), "123");
    let id = &items[3];
    assert_eq!(val(id, "first name"), "Alice");
    assert_eq!(
        id.field("first name").unwrap().section.as_deref(),
        Some("Name")
    );
}

#[test]
fn template_tag_dedups_case_insensitively_with_source_tags() {
    // The source already tags the item "Login" / "CARD": keep its spelling and position, do
    // not add a second copy. Items without such a tag get the lowercase template tag first.
    let data = export(vec![
        json!({"state": "active", "categoryUuid": "001",
               "details": {}, "overview": {"title": "A", "tags": ["work", "Login"]}}),
        json!({"state": "active", "categoryUuid": "002",
               "details": {}, "overview": {"title": "B", "tags": ["CARD"]}}),
        json!({"state": "active", "categoryUuid": "004",
               "details": {}, "overview": {"title": "C", "tags": ["x"]}}),
    ]);
    let items = import_1pux(&archive(&data), Uuid::nil(), NOW).unwrap();
    assert_eq!(items[0].tags, ["work", "Login"]);
    assert_eq!(items[1].tags, ["CARD"]);
    assert_eq!(items[2].tags, ["identity", "x"]);
}

#[test]
fn malformed_inputs() {
    let bad_json = zip_with(&[("export.data", b"{ not json")]);
    assert!(matches!(
        import_1pux(&bad_json, Uuid::nil(), NOW),
        Err(ImportError::Malformed(_))
    ));
    let no_data = zip_with(&[("export.attributes", b"{}")]);
    assert!(matches!(
        import_1pux(&no_data, Uuid::nil(), NOW),
        Err(ImportError::Malformed(_))
    ));
    assert!(matches!(
        import_1pux(b"not a zip", Uuid::nil(), NOW),
        Err(ImportError::Malformed(_))
    ));
}

#[test]
fn malformed_error_does_not_leak_values() {
    let bad = zip_with(&[("export.data", br#"{"password": "hunter2" oops"#)]);
    let err = import_1pux(&bad, Uuid::nil(), NOW).err().unwrap();
    assert!(!err.to_string().contains("hunter2"));
}

#[test]
fn zero_items_is_ok() {
    assert!(
        import_1pux(&archive(&export(vec![])), Uuid::nil(), NOW)
            .unwrap()
            .is_empty()
    );
    assert!(
        import_1pux(&archive(&json!({})), Uuid::nil(), NOW)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn oversized_export_data_is_malformed() {
    // Valid JSON padded with whitespace past the 64 MiB cap.
    let mut big = br#"{"accounts":[]}"#.to_vec();
    big.resize(64 * 1024 * 1024 + 16, b' ');
    let z = zip_with(&[("export.data", &big)]);
    assert!(matches!(
        import_1pux(&z, Uuid::nil(), NOW),
        Err(ImportError::Malformed(_))
    ));
}

#[test]
fn odd_month_year_kept_raw_and_empty_section_is_none() {
    let data = export(vec![json!({"state": "active", "categoryUuid": "002",
        "details": {"sections": [{"title": "", "fields": [
            {"title": "exp", "value": {"monthYear": 20291}}]}]},
        "overview": {"title": "C"}})]);
    let items = import_1pux(&archive(&data), Uuid::nil(), NOW).unwrap();
    let f = items[0].field("exp").unwrap();
    assert_eq!(f.value.expose_secret(), "20291");
    assert_eq!(f.section, None);
}

#[test]
fn duplicate_field_names_are_deduplicated_in_linear_time() {
    let fields: Vec<Value> = (0..5000)
        .map(|i| json!({"title": "dup", "id": format!("i{i}"), "value": {"string": format!("v{i}")}}))
        .collect();
    let data = export(vec![json!({
        "uuid": "a", "createdAt": 1, "updatedAt": 2, "state": "active", "categoryUuid": "001",
        "overview": {"title": "Many"},
        "details": {"sections": [{"title": "S", "fields": fields}]}
    })]);
    let bytes = archive(&data);
    let start = std::time::Instant::now();
    let items = import_1pux(&bytes, Uuid::nil(), NOW).unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
    let item = &items[0];
    assert_eq!(item.fields.len(), 5000);
    let names: Vec<&str> = item.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(&names[..4], ["dup", "dup (2)", "dup (3)", "dup (4)"]);
    assert_eq!(names[4999], "dup (5000)");
    let unique: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(unique.len(), 5000);
}

#[test]
fn literal_suffixed_name_does_not_collide_with_generated_suffix() {
    let f =
        |id: &str, title: &str, v: &str| json!({"title": title, "id": id, "value": {"string": v}});
    let data = export(vec![json!({
        "uuid": "a", "createdAt": 1, "updatedAt": 2, "state": "active", "categoryUuid": "001",
        "overview": {"title": "T"},
        "details": {"sections": [{"title": "S", "fields": [
            f("1", "x (2)", "literal"), f("2", "x", "first"), f("3", "x", "second"), f("4", "x", "third"),
        ]}]}
    })]);
    let items = import_1pux(&archive(&data), Uuid::nil(), NOW).unwrap();
    let names: Vec<&str> = items[0].fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["x (2)", "x", "x (3)", "x (4)"]);
    assert_eq!(val(&items[0], "x (2)"), "literal");
}
