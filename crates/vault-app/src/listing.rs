//! Derived list data (specs/05-ui.md §3): the filtered, sorted item ids shown in the
//! item list, their A–Z group rows, and the sidebar counts.
//!
//! Pure functions over an `UnlockedVault`; `AppState` caches the results and recomputes
//! them only when the query, filter, sort or vault contents change.

use std::rc::Rc;

use gpui::SharedString;
use vault_core::search::{Query, search};
use vault_core::{ExposeSecret, Field, FieldKind, Item, ItemKind, UnlockedVault, Uuid};

use crate::state::{Filter, Sort};
use crate::text;

/// One row of the item list: an A–Z group header or an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    Header(SharedString),
    Item(Uuid),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// Visible items in display order. Selection moves through this.
    pub items: Vec<Uuid>,
    /// `items` plus group headers. Shared with the list element's render closure.
    pub rows: Rc<Vec<Row>>,
}

impl Listing {
    /// Index into `rows` of the item `id`.
    pub fn row_of(&self, id: Uuid) -> Option<usize> {
        self.rows.iter().position(|r| *r == Row::Item(id))
    }
}

/// Per-section item counts for the sidebar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    pub all: usize,
    pub favorites: usize,
    /// Indexed like `ItemKind::ALL`.
    pub kinds: [usize; 4],
    /// Tags case-insensitively merged, sorted alphabetically, with their item counts.
    pub tags: Vec<(String, usize)>,
}

impl Counts {
    pub fn kind(&self, kind: ItemKind) -> usize {
        ItemKind::ALL
            .iter()
            .position(|k| *k == kind)
            .map_or(0, |i| self.kinds[i])
    }
}

pub fn counts(vault: &UnlockedVault) -> Counts {
    let mut counts = Counts::default();
    // (lowercase key, display spelling, count)
    let mut tags: Vec<(String, String, usize)> = Vec::new();
    for item in vault.items() {
        counts.all += 1;
        counts.favorites += usize::from(item.favorite);
        if let Some(i) = ItemKind::ALL.iter().position(|k| *k == item.kind) {
            counts.kinds[i] += 1;
        }
        let mut seen: Vec<String> = Vec::new();
        for tag in &item.tags {
            let key = tag.to_lowercase();
            if seen.contains(&key) {
                continue;
            }
            match tags.iter_mut().find(|t| t.0 == key) {
                Some(t) => t.2 += 1,
                None => tags.push((key.clone(), tag.clone(), 1)),
            }
            seen.push(key);
        }
    }
    tags.sort_by(|a, b| a.0.cmp(&b.0));
    counts.tags = tags.into_iter().map(|(_, name, n)| (name, n)).collect();
    counts
}

/// Group label for A–Z sorting: the uppercased first letter, or `#` for anything else.
pub fn group_label(title: &str) -> String {
    match title.trim_start().chars().next() {
        Some(c) if c.is_alphabetic() => c.to_uppercase().collect(),
        _ => "#".to_owned(),
    }
}

/// Filter, rank and sort the vault's live items.
///
/// With a search query the order is the core's relevance ranking and there are no group
/// headers. Without one, `sort` applies and A–Z adds a header row per first letter.
/// Core items have no creation time, so "recently created" sorts by `modified_at` too.
pub fn compute(vault: &UnlockedVault, query: &str, filter: &Filter, sort: Sort) -> Listing {
    let q = Query {
        text: query,
        kind: match filter {
            Filter::Kind(k) => Some(*k),
            _ => None,
        },
        tag: match filter {
            Filter::Tag(t) => Some(t.as_str()),
            _ => None,
        },
        favorites_only: *filter == Filter::Favorites,
    };
    let mut hits = search(vault, &q);
    let searching = !query.trim().is_empty();
    if !searching {
        match sort {
            Sort::Alphabetical => hits.sort_by_cached_key(|i| {
                let label = group_label(&i.title);
                (label != "#", label, i.title.to_lowercase(), i.id)
            }),
            Sort::RecentlyModified => hits.sort_by(|a, b| {
                b.modified_at
                    .cmp(&a.modified_at)
                    .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
            }),
        }
    }

    let grouped = !searching && sort == Sort::Alphabetical;
    let mut rows = Vec::with_capacity(hits.len() + 27);
    let mut current: Option<String> = None;
    for item in &hits {
        if grouped {
            let label = group_label(&item.title);
            if current.as_deref() != Some(label.as_str()) {
                rows.push(Row::Header(label.clone().into()));
                current = Some(label);
            }
        }
        rows.push(Row::Item(item.id));
    }
    Listing {
        items: hits.iter().map(|i| i.id).collect(),
        rows: Rc::new(rows),
    }
}

/// Second line of a list row: username, card last four, or the note's first line.
pub fn subtitle(item: &Item) -> String {
    match item.kind {
        ItemKind::Card => item
            .field("number")
            .and_then(|f| text::last4(f.value.expose_secret()))
            .map(|l| format!("•••• {l}"))
            .unwrap_or_default(),
        ItemKind::Note => item
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Notes)
            .and_then(|f| {
                f.value
                    .expose_secret()
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .map(|l| text::truncate(l, 80))
            })
            .unwrap_or_default(),
        ItemKind::Login | ItemKind::Identity => username_field(item)
            .map(|f| f.value.expose_secret().to_string())
            .unwrap_or_default(),
    }
}

/// The field ⌘⇧U copies and the list subtitle shows: `username`, else the first email.
/// A card's number field: masked as `•••• 4242` until revealed (main detail and the
/// backup viewer share this rule).
pub fn is_card_number(item: &Item, field: &Field) -> bool {
    item.kind == ItemKind::Card && field.name == "number"
}

pub fn username_field(item: &Item) -> Option<&Field> {
    item.field("username")
        .or_else(|| item.fields.iter().find(|f| f.kind == FieldKind::Email))
}

/// Deterministic palette index for an item's letter avatar.
pub fn avatar_slot(id: Uuid, palette_len: usize) -> usize {
    let h = id.as_u128();
    let folded = (h as u64) ^ ((h >> 64) as u64);
    (folded % palette_len.max(1) as u64) as usize
}

/// First letter of the title for the avatar, `?` when the title is blank.
pub fn avatar_letter(title: &str) -> String {
    title
        .trim_start()
        .chars()
        .next()
        .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, SecretString};

    fn vault() -> UnlockedVault {
        let pw = SecretString::new("pw".into());
        UnlockedVault::create(&pw, KdfParams::for_tests(), Uuid::new_v4())
    }

    fn add(v: &mut UnlockedVault, kind: ItemKind, title: &str, now: u64) -> Uuid {
        let item = Item::new(kind, title, v.device_id(), now);
        v.insert(item, now)
    }

    #[test]
    fn groups_alphabetically_with_hash_first() {
        let mut v = vault();
        add(&mut v, ItemKind::Login, "beta", 1);
        add(&mut v, ItemKind::Login, "Alpha", 2);
        add(&mut v, ItemKind::Login, "1Password import", 3);
        add(&mut v, ItemKind::Login, "_hidden", 4);
        add(&mut v, ItemKind::Login, "Apple", 5);
        let l = compute(&v, "", &Filter::All, Sort::Alphabetical);
        let headers: Vec<_> = l
            .rows
            .iter()
            .filter_map(|r| match r {
                Row::Header(h) => Some(h.to_string()),
                Row::Item(_) => None,
            })
            .collect();
        assert_eq!(headers, ["#", "A", "B"]);
        assert_eq!(l.items.len(), 5);
        assert_eq!(l.rows.len(), 8);
    }

    #[test]
    fn recent_sort_and_search_have_no_headers() {
        let mut v = vault();
        let old = add(&mut v, ItemKind::Login, "Old", 10);
        let new = add(&mut v, ItemKind::Login, "New", 20);
        let l = compute(&v, "", &Filter::All, Sort::RecentlyModified);
        assert_eq!(l.items, [new, old]);
        assert!(l.rows.iter().all(|r| matches!(r, Row::Item(_))));
        let l = compute(&v, "ol", &Filter::All, Sort::Alphabetical);
        assert_eq!(l.items, [old]);
        assert_eq!(*l.rows, [Row::Item(old)]);
    }

    #[test]
    fn filters_and_counts() {
        let mut v = vault();
        let gh = add(&mut v, ItemKind::Login, "GitHub", 1);
        add(&mut v, ItemKind::Note, "Wifi", 2);
        let card = add(&mut v, ItemKind::Card, "Visa", 3);
        v.update(gh, 4, |it| {
            it.favorite = true;
            it.tags = vec!["Infra".into(), "work".into()];
        })
        .unwrap();
        v.update(card, 5, |it| it.tags = vec!["infra".into()])
            .unwrap();

        let fav = compute(&v, "", &Filter::Favorites, Sort::Alphabetical);
        assert_eq!(fav.items, [gh]);
        let cards = compute(&v, "", &Filter::Kind(ItemKind::Card), Sort::Alphabetical);
        assert_eq!(cards.items, [card]);
        let infra = compute(&v, "", &Filter::Tag("infra".into()), Sort::Alphabetical);
        assert_eq!(infra.items.len(), 2);

        let c = counts(&v);
        assert_eq!((c.all, c.favorites), (3, 1));
        assert_eq!(c.kind(ItemKind::Note), 1);
        assert_eq!(c.tags.len(), 2);
        assert_eq!(c.tags[0].0.to_lowercase(), "infra");
        assert_eq!(c.tags[0].1, 2);
        assert_eq!(c.tags[1], ("work".to_owned(), 1));
    }

    #[test]
    fn subtitles() {
        let mut card = Item::new(ItemKind::Card, "Visa", Uuid::new_v4(), 1);
        card.fields.push(Field::new(
            "number",
            FieldKind::Text,
            SecretString::new("4242 4242 4242 4242".into()),
            1,
        ));
        assert_eq!(subtitle(&card), "•••• 4242");
        let mut note = Item::new(ItemKind::Note, "n", Uuid::new_v4(), 1);
        note.fields.push(Field::new(
            "notes",
            FieldKind::Notes,
            SecretString::new("\n  first line\nsecond".into()),
            1,
        ));
        assert_eq!(subtitle(&note), "first line");
        let mut login = Item::new(ItemKind::Login, "l", Uuid::new_v4(), 1);
        login.fields.push(Field::new(
            "username",
            FieldKind::Text,
            SecretString::new("chris".into()),
            1,
        ));
        assert_eq!(subtitle(&login), "chris");
    }

    #[test]
    fn avatar_is_deterministic() {
        let id = Uuid::new_v4();
        assert_eq!(avatar_slot(id, 8), avatar_slot(id, 8));
        assert!(avatar_slot(id, 8) < 8);
        assert_eq!(avatar_letter("  github"), "G");
        assert_eq!(avatar_letter(""), "?");
    }
}
