//! New-item templates (specs/05-ui.md §2.3): presets of fields plus one tag. Items have
//! no category since 2026-10-30; a template only decides the starting fields and tag.

use gpui_kit_assets::IconName;
use vault_core::{Field, FieldKind, Item, Millis, SecretString, Uuid};

/// A template offered by "New" (⌘N and "+ New"), in menu order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Template {
    Login,
    Note,
    Card,
    Identity,
}

impl Template {
    pub const ALL: [Template; 4] = [
        Template::Login,
        Template::Note,
        Template::Card,
        Template::Identity,
    ];

    /// Menu label.
    pub fn label(self) -> &'static str {
        match self {
            Template::Login => "Login",
            Template::Note => "Note",
            Template::Card => "Card",
            Template::Identity => "Identity",
        }
    }

    /// The tag the template adds.
    pub fn tag(self) -> &'static str {
        match self {
            Template::Login => "login",
            Template::Note => "note",
            Template::Card => "card",
            Template::Identity => "identity",
        }
    }

    pub fn icon(self) -> IconName {
        match self {
            Template::Login => IconName::KeyRound,
            Template::Note => IconName::StickyNote,
            Template::Card => IconName::CreditCard,
            Template::Identity => IconName::IdCard,
        }
    }

    /// Preset fields: (name, kind), all starting empty. Names are natural English labels
    /// (orchestrator decision 2026-10-31): "Website" for the URL field, "CVV", "First
    /// name". Nothing looks a field up by these names case-sensitively, and the URL
    /// field is found by its kind.
    pub fn fields(self) -> &'static [(&'static str, FieldKind)] {
        match self {
            Template::Login => &[
                ("Username", FieldKind::Text),
                ("Password", FieldKind::Password),
                ("Website", FieldKind::Url),
                ("Notes", FieldKind::Notes),
            ],
            Template::Note => &[("Notes", FieldKind::Notes)],
            Template::Card => &[
                ("Number", FieldKind::Text),
                ("Expiry", FieldKind::MonthYear),
                ("CVV", FieldKind::Password),
                ("Name", FieldKind::Text),
            ],
            Template::Identity => &[
                ("First name", FieldKind::Text),
                ("Last name", FieldKind::Text),
                ("Email", FieldKind::Email),
                ("Phone", FieldKind::Text),
                ("Address", FieldKind::Notes),
            ],
        }
    }

    /// Adds this template's fields and tag to `item`. The tag is not added twice
    /// (case-insensitive).
    pub fn apply(self, item: &mut Item, now: Millis) {
        item.fields.extend(
            self.fields().iter().map(|(name, kind)| {
                Field::new(*name, *kind, SecretString::new(String::new()), now)
            }),
        );
        add_tag(&mut item.tags, self.tag());
    }

    /// A new item from this template.
    pub fn new_item(self, title: impl Into<String>, device_id: Uuid, now: Millis) -> Item {
        let mut item = Item::new(title, device_id, now);
        self.apply(&mut item, now);
        item
    }
}

/// Appends `tag` unless `tags` already holds it (case-insensitive).
pub fn add_tag(tags: &mut Vec<String>, tag: &str) {
    if !has_tag(tags, tag) {
        tags.push(tag.to_owned());
    }
}

/// The one rule for comparing tags: surrounding whitespace ignored, Unicode
/// case-insensitive. Used by `has_tag`, `tag_icon`, card masking and the editor's dedupe.
pub fn tag_matches(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// Whether `tags` holds `tag` (see `tag_matches`).
pub fn has_tag(tags: &[String], tag: &str) -> bool {
    tags.iter().any(|t| tag_matches(t, tag))
}

/// Sidebar glyph for a tag: the template icon for the four template tags, else the
/// generic tag glyph.
pub fn tag_icon(tag: &str) -> IconName {
    Template::ALL
        .into_iter()
        .find(|t| tag_matches(t.tag(), tag))
        .map_or(IconName::Tag, Template::icon)
}

/// Whether the item is a card, which masks its `number` field and gives it a last-4 list
/// subtitle. True when it carries the `card` template tag, or when it predates templates
/// and still holds the removed `kind: "card"` key in its extras (vault-core keeps that key
/// verbatim). Masking follows the tag: removing the `card` tag from a templated card
/// unmasks its number field.
pub fn is_card(item: &Item) -> bool {
    has_tag(&item.tags, Template::Card.tag()) || legacy_kind(item, Template::Card.tag())
}

/// Whether the item's extras hold the pre-template `kind` key with value `kind`.
fn legacy_kind(item: &Item, kind: &str) -> bool {
    item.extras.iter().any(|(k, v)| {
        k.as_text() == Some("kind") && v.as_text().is_some_and(|v| tag_matches(v, kind))
    })
}

/// A bare item tagged like `template` (no preset fields), for tests that build items
/// by hand.
#[cfg(test)]
pub fn tagged(template: Template, title: impl Into<String>, device_id: Uuid, now: Millis) -> Item {
    let mut item = Item::new(title, device_id, now);
    item.tags.push(template.tag().to_owned());
    item
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::ExposeSecret as _;

    #[test]
    fn templates_add_their_fields_and_one_tag() {
        for t in Template::ALL {
            let item = t.new_item("x", Uuid::new_v4(), 1);
            assert_eq!(item.tags, [t.tag()]);
            let fields: Vec<_> = item
                .fields
                .iter()
                .map(|f| (f.name.as_str(), f.kind))
                .collect();
            assert_eq!(fields, t.fields());
            assert!(
                item.fields
                    .iter()
                    .all(|f| f.value.expose_secret().is_empty())
            );
        }
        let card = Template::Card.new_item("Visa", Uuid::new_v4(), 1);
        assert!(is_card(&card));
        assert_eq!(card.fields[0].name, "Number");
        // The label table: natural English labels, each starting with a capital.
        let names = |t: Template| t.fields().iter().map(|(n, _)| *n).collect::<Vec<_>>();
        assert_eq!(
            names(Template::Login),
            ["Username", "Password", "Website", "Notes"]
        );
        assert_eq!(names(Template::Note), ["Notes"]);
        assert_eq!(names(Template::Card), ["Number", "Expiry", "CVV", "Name"]);
        assert_eq!(
            names(Template::Identity),
            ["First name", "Last name", "Email", "Phone", "Address"]
        );
        for t in Template::ALL {
            for (name, _) in t.fields() {
                assert_eq!(*name, crate::text::capitalize_first(name), "{name}");
            }
        }
        // The website is found by kind, whatever its label.
        let mut login = Template::Login.new_item("x", Uuid::new_v4(), 1);
        login.fields[2].value = SecretString::new("https://github.com".into());
        assert!(matches!(
            crate::icon::automatic(&login),
            crate::icon::IconSpec::Logo { slug: "github", .. }
        ));
        assert_eq!(card.fields[1].kind, FieldKind::MonthYear);
        let id = Template::Identity.new_item("Me", Uuid::new_v4(), 1);
        assert_eq!(id.field("Phone").map(|f| f.kind), Some(FieldKind::Text));
        assert!(
            Template::ALL
                .iter()
                .all(|t| t.fields().iter().all(|f| !f.1.is_other()))
        );
    }

    #[test]
    fn template_tag_is_deduplicated_case_insensitively() {
        let mut item = Item::new("x", Uuid::new_v4(), 1);
        item.tags = vec!["Work".into(), "LOGIN".into()];
        Template::Login.apply(&mut item, 1);
        assert_eq!(item.tags, ["Work", "LOGIN"]);
        Template::Note.apply(&mut item, 1);
        assert_eq!(item.tags, ["Work", "LOGIN", "note"]);
    }

    /// One matching rule everywhere: trimmed and Unicode case-insensitive.
    #[test]
    fn tag_matching_is_trimmed_and_unicode_case_insensitive() {
        assert!(tag_matches(" Ärzte ", "ärzte"));
        assert!(has_tag(&["ÄRZTE".to_owned()], "ärzte"));
        assert!(!tag_matches("cards", "card"));
        assert_eq!(tag_icon(" Card "), IconName::CreditCard);
        let mut item = Item::new("x", Uuid::new_v4(), 1);
        item.tags = vec![" CARD ".into()];
        assert!(is_card(&item), "masking uses the same rule as the icon");
    }

    /// An item from before templates keeps `kind: "card"` in its extras and is still a
    /// card; removing the `card` tag from a templated card makes it an ordinary item.
    #[test]
    fn legacy_card_kind_counts_and_removing_the_tag_unmasks() {
        let mut old = Item::new("Old Visa", Uuid::new_v4(), 1);
        old.extras.push(("kind".into(), "card".into()));
        assert!(is_card(&old));
        let mut login = Item::new("Old login", Uuid::new_v4(), 1);
        login.extras.push(("kind".into(), "login".into()));
        login.extras.push(("note".into(), "card".into()));
        assert!(!is_card(&login), "only the `kind` key counts");

        let mut card = Template::Card.new_item("Visa", Uuid::new_v4(), 1);
        assert!(is_card(&card));
        card.tags.clear();
        assert!(!is_card(&card));
    }

    #[test]
    fn tag_icons() {
        assert_eq!(tag_icon("login"), IconName::KeyRound);
        assert_eq!(tag_icon("Note"), IconName::StickyNote);
        assert_eq!(tag_icon("CARD"), IconName::CreditCard);
        assert_eq!(tag_icon("identity"), IconName::IdCard);
        assert_eq!(tag_icon("logins"), IconName::Tag);
        assert_eq!(tag_icon("work"), IconName::Tag);
    }
}
