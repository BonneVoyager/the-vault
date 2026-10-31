//! In-memory ranked search over unlocked items (`02-core-api.md` "search").

use secrecy::ExposeSecret;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::item::{FieldKind, Item};
use crate::vault::UnlockedVault;

/// Search filters. There is no category filter: item kinds were removed on 2026-10-30, and
/// template tags (`login`, `note`, ...) are matched through `tag` like any other tag.
pub struct Query<'a> {
    pub text: &'a str,
    pub tag: Option<&'a str>,
    pub favorites_only: bool,
}

/// NFKC + lowercase. Returns a zeroizing buffer because callers fold url / username / notes
/// field values, which are secrets; the NFKC intermediate is zeroized too.
fn fold(s: &str) -> Zeroizing<String> {
    let nfkc: Zeroizing<String> = Zeroizing::new(s.nfkc().collect());
    Zeroizing::new(nfkc.to_lowercase())
}

/// Host part of a URL-ish string: scheme, userinfo, port, path and leading `www.` stripped.
fn host_of(url: &str) -> Zeroizing<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    let host = authority.split(':').next().unwrap_or("");
    let host = fold(host);
    Zeroizing::new(host.strip_prefix("www.").unwrap_or(&host).to_owned())
}

/// Section headings ([`FieldKind::Section`]) are not searched: neither their name nor their
/// (ignored) value takes part, even when the heading is named `username`.
fn rank(item: &Item, q: &str) -> Option<u8> {
    if q.is_empty() {
        return Some(0);
    }
    let title = fold(&item.title);
    if title.starts_with(q) {
        return Some(0);
    }
    if title.contains(q) {
        return Some(1);
    }
    let fields = || item.fields.iter().filter(|f| f.kind != FieldKind::Section);
    if fields().any(|f| f.kind == FieldKind::Url && host_of(f.value.expose_secret()).contains(q)) {
        return Some(2);
    }
    if fields().any(|f| {
        (f.name.eq_ignore_ascii_case("username") || f.kind == FieldKind::Email)
            && fold(f.value.expose_secret()).contains(q)
    }) {
        return Some(3);
    }
    if item.tags.iter().any(|t| fold(t).contains(q)) {
        return Some(4);
    }
    if fields().any(|f| f.kind == FieldKind::Notes && fold(f.value.expose_secret()).contains(q)) {
        return Some(5);
    }
    None
}

/// Filter by tag / favourite, then rank by text. Ties break by title.
pub fn search<'a>(vault: &'a UnlockedVault, q: &Query) -> Vec<&'a Item> {
    let text = fold(q.text.trim());
    let tag = q.tag.map(fold);
    let mut hits: Vec<(u8, Zeroizing<String>, &'a Item)> = vault
        .items()
        .filter(|i| !q.favorites_only || i.favorite)
        .filter(|i| {
            tag.as_ref()
                .is_none_or(|t| i.tags.iter().any(|x| fold(x).as_str() == t.as_str()))
        })
        .filter_map(|i| rank(i, &text).map(|r| (r, fold(&i.title), i)))
        .collect();
    hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_str().cmp(b.1.as_str())));
    hits.into_iter().map(|(_, _, i)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Field;
    use secrecy::SecretString;
    use uuid::Uuid;

    fn with(name: &str, kind: FieldKind, v: &str) -> Item {
        let mut i = Item::new("T", Uuid::nil(), 1);
        i.fields
            .push(Field::new(name, kind, SecretString::new(v.to_owned()), 1));
        i
    }

    #[test]
    fn username_field_name_is_case_insensitive() {
        for name in ["username", "Username", "USERNAME"] {
            assert_eq!(
                rank(&with(name, FieldKind::Text, "zed@x.org"), "zed"),
                Some(3)
            );
        }
        // Other ranks are unchanged.
        assert_eq!(rank(&with("other", FieldKind::Text, "zed"), "zed"), None);
        assert_eq!(
            rank(&with("e", FieldKind::Email, "zed@x.org"), "zed"),
            Some(3)
        );
        assert_eq!(rank(&with("n", FieldKind::Notes, "zed"), "zed"), Some(5));
        assert_eq!(
            rank(&with("url", FieldKind::Url, "https://zed.dev"), "zed"),
            Some(2)
        );
    }
}
