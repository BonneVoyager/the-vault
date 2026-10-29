//! 1PUX import (`import_1pux`).

use std::io::Write;

use serde_json::{Value, json};
use vault_core::import::{ImportError, import_1pux};
use vault_core::{ExposeSecret, FieldKind, Item, ItemKind, Uuid};

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
    assert_eq!(
        items.iter().map(|i| i.kind).collect::<Vec<_>>(),
        [
            ItemKind::Login,
            ItemKind::Note,
            ItemKind::Card,
            ItemKind::Identity
        ]
    );
    assert!(items.iter().all(|i| i.title != "Old"));
    assert_eq!(items[3].title, "Untitled");
}

#[test]
fn login_fields_tags_favorite_history() {
    let items = import_1pux(&archive(&sample()), Uuid::nil(), NOW).unwrap();
    let login = &items[0];
    assert_eq!(login.title, "Example");
    assert!(login.favorite);
    assert_eq!(login.tags, ["work", "dev"]);
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
