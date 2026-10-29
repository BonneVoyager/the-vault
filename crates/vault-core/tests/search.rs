use vault_core::search::{Query, search};
use vault_core::{Field, FieldKind, Item, ItemKind, KdfParams, SecretString, UnlockedVault, Uuid};

fn field(name: &str, kind: FieldKind, v: &str) -> Field {
    Field::new(name, kind, SecretString::new(v.to_owned()), 1)
}

fn vault_with(items: Vec<Item>) -> UnlockedVault {
    let dev = Uuid::nil();
    let mut v = UnlockedVault::create(&SecretString::new("pw".into()), KdfParams::for_tests(), dev);
    for i in items {
        v.insert(i, 1);
    }
    v
}

fn item(kind: ItemKind, title: &str) -> Item {
    Item::new(kind, title, Uuid::nil(), 1)
}

fn titles(v: &[&Item]) -> Vec<String> {
    v.iter().map(|i| i.title.clone()).collect()
}

fn q(text: &str) -> Query<'_> {
    Query {
        text,
        kind: None,
        tag: None,
        favorites_only: false,
    }
}

#[test]
fn ranking_order() {
    let mut by_notes = item(ItemKind::Login, "F notes");
    by_notes
        .fields
        .push(field("notes", FieldKind::Notes, "see zed here"));
    let mut by_tag = item(ItemKind::Login, "E tag");
    by_tag.tags.push("zed".into());
    let mut by_user = item(ItemKind::Login, "D user");
    by_user
        .fields
        .push(field("username", FieldKind::Text, "zed@x.org"));
    let mut by_host = item(ItemKind::Login, "C host");
    by_host
        .fields
        .push(field("url", FieldKind::Url, "https://www.zed.dev/login"));
    let by_sub = item(ItemKind::Login, "B my zed");
    let by_prefix = item(ItemKind::Login, "Zed prefix");
    let none = item(ItemKind::Login, "unrelated");
    let v = vault_with(vec![
        by_notes, by_tag, by_user, by_host, by_sub, by_prefix, none,
    ]);
    let r = search(&v, &q("zed"));
    assert_eq!(
        titles(&r),
        [
            "Zed prefix",
            "B my zed",
            "C host",
            "D user",
            "E tag",
            "F notes"
        ]
    );
}

#[test]
fn host_match_ignores_path_and_scheme() {
    let mut a = item(ItemKind::Login, "a");
    a.fields
        .push(field("url", FieldKind::Url, "https://example.com/zed"));
    let v = vault_with(vec![a]);
    assert!(search(&v, &q("zed")).is_empty());
    assert_eq!(search(&v, &q("example")).len(), 1);
}

#[test]
fn empty_text_returns_all_sorted_by_title() {
    let v = vault_with(vec![item(ItemKind::Login, "b"), item(ItemKind::Note, "a")]);
    assert_eq!(titles(&search(&v, &q(""))), ["a", "b"]);
}

#[test]
fn filters() {
    let mut fav = item(ItemKind::Login, "fav");
    fav.favorite = true;
    fav.tags.push("work".into());
    let note = item(ItemKind::Note, "note");
    let v = vault_with(vec![fav, note]);
    let k = Query {
        kind: Some(ItemKind::Note),
        ..q("")
    };
    assert_eq!(titles(&search(&v, &k)), ["note"]);
    let t = Query {
        tag: Some("WORK"),
        ..q("")
    };
    assert_eq!(titles(&search(&v, &t)), ["fav"]);
    let f = Query {
        favorites_only: true,
        ..q("")
    };
    assert_eq!(titles(&search(&v, &f)), ["fav"]);
}

#[test]
fn deleted_items_excluded() {
    let a = item(ItemKind::Login, "gone");
    let id = a.id;
    let mut v = vault_with(vec![a]);
    v.delete(id, 2).unwrap();
    assert!(search(&v, &q("gone")).is_empty());
}

#[test]
fn unicode_and_case_insensitive() {
    let v = vault_with(vec![item(ItemKind::Login, "caf\u{e9} Bar")]);
    assert_eq!(search(&v, &q("CAF\u{c9}")).len(), 1);
    // Decomposed e + combining acute normalises to the same text.
    assert_eq!(search(&v, &q("cafe\u{301}")).len(), 1);
    assert_eq!(search(&v, &q("bar")).len(), 1);
}
