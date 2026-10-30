use vault_core::import::{CsvMapping, ImportError, import_csv};
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, KdfParams, SecretString, UnlockedVault, Uuid, export_csv,
};

fn field(name: &str, kind: FieldKind, v: &str) -> Field {
    Field::new(name, kind, SecretString::new(v.to_owned()), 1)
}

fn login(title: &str, user: &str, pw: &str) -> Item {
    let mut i = Item::new(title, Uuid::nil(), 1);
    i.fields.push(field("username", FieldKind::Text, user));
    i.fields.push(field("password", FieldKind::Password, pw));
    i
}

fn get<'a>(i: &'a Item, n: &str) -> &'a str {
    i.field(n).map_or("", |f| f.value.expose_secret().as_str())
}

fn vault(items: Vec<Item>) -> UnlockedVault {
    let mut v = UnlockedVault::create(
        &SecretString::new("pw".into()),
        KdfParams::for_tests(),
        Uuid::nil(),
    );
    for i in items {
        v.insert(i, 1);
    }
    v
}

#[test]
fn export_then_import_round_trips() {
    let mut tricky = login("a, \"b\"", "us,er", "p\nw\"d");
    tricky
        .fields
        .push(field("notes", FieldKind::Notes, "line1\nline2, with comma"));
    tricky
        .fields
        .push(field("url", FieldKind::Url, "https://x.test"));
    tricky.fields.push(field(
        "totp",
        FieldKind::Totp,
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",
    ));
    let v = vault(vec![
        tricky,
        login("plain", "u", "p"),
        Item::new("n", Uuid::nil(), 1),
    ]);

    let out = export_csv(&v);
    let dev = Uuid::new_v4();
    let imported = import_csv(&out.0, &CsvMapping::default(), dev, 99).unwrap();
    assert_eq!(imported.len(), 3);

    let mut orig: Vec<&Item> = v.items().collect();
    orig.sort_by(|a, b| a.title.cmp(&b.title));
    let mut got: Vec<&Item> = imported.iter().collect();
    got.sort_by(|a, b| a.title.cmp(&b.title));
    for (o, g) in orig.iter().zip(&got) {
        assert_eq!(o.title, g.title);
        assert_eq!(g.tags, ["login"], "CSV rows get the login template tag");
        assert_eq!(g.device_id, dev);
        assert_eq!(g.modified_at, 99);
        for n in ["username", "password", "url", "notes", "totp"] {
            assert_eq!(get(o, n), get(g, n), "{} / {n}", o.title);
        }
    }
    assert_ne!(imported[0].id, imported[1].id);
    // Empty cells produce no field.
    let note = got.iter().find(|i| i.title == "n").unwrap();
    assert!(note.fields.is_empty());
}

#[test]
fn export_has_no_category_gate_on_credentials() {
    // Item kinds are gone (2026-10-30): a "note" (by template tag) that carries a password
    // field exports it like any other item, and an item without one gets an empty cell.
    let mut n = Item::new("n", Uuid::nil(), 1);
    n.tags.push("note".into());
    n.fields
        .push(field("password", FieldKind::Password, "exported-pw"));
    n.fields.push(field("notes", FieldKind::Notes, "body"));
    let bare = Item::new("bare", Uuid::nil(), 1);
    let out = export_csv(&vault(vec![n, bare]));
    let text = String::from_utf8(out.0.clone()).unwrap();
    assert!(text.starts_with("title,username,password,url,notes,totp"));
    assert!(text.contains("n,,exported-pw,,body,"));
    assert!(text.contains("bare,,,,,"));
}

#[test]
fn missing_column() {
    let csv = b"title,username\na,b\n";
    match import_csv(csv, &CsvMapping::default(), Uuid::nil(), 1) {
        Err(ImportError::MissingColumn(c)) => assert_eq!(c, "password"),
        other => panic!("unexpected: {:?}", other.map(|v| v.len())),
    }
}

#[test]
fn custom_mapping_and_headerless() {
    let m = CsvMapping {
        title: "name".into(),
        username: "login".into(),
        password: "pass".into(),
        url: String::new(),
        notes: String::new(),
        totp: None,
        has_header: true,
    };
    let items = import_csv(b"Name,Login,Pass\nx,u,p\n", &m, Uuid::nil(), 1).unwrap();
    assert_eq!(get(&items[0], "username"), "u");

    let m = CsvMapping {
        title: "0".into(),
        username: "1".into(),
        password: "2".into(),
        url: String::new(),
        notes: String::new(),
        totp: None,
        has_header: false,
    };
    let items = import_csv(b"x,u,p\n", &m, Uuid::nil(), 1).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title, "x");
    assert_eq!(get(&items[0], "password"), "p");
}
