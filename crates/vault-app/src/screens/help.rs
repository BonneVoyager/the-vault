//! Help ▸ Vault Help (05 §2.5): `docs/help.md`, bundled at compile time and shown
//! read-only through the notes Markdown renderer (links open in the browser as in notes;
//! GFM tables render). The page's first `# ` heading becomes the sheet title.

use gpui::{Entity, IntoElement};

use super::main::notes::notes_view;
use crate::state::AppState;

/// The help page: the single source, edited by the owner.
const SOURCE: &str = include_str!("../../../../docs/help.md");

/// `source` split into its leading `# ` heading and the rest; no heading gives a fixed
/// title and the whole page.
fn split(source: &str) -> (&str, &str) {
    match source.strip_prefix("# ") {
        Some(rest) => {
            let (title, body) = rest.split_once('\n').unwrap_or((rest, ""));
            (title.trim(), body)
        }
        None => ("Vault Help", source),
    }
}

/// The sheet title: the page's first heading.
pub fn title() -> &'static str {
    split(SOURCE).0
}

/// The page body below the title.
pub fn help_view(state: &Entity<AppState>) -> impl IntoElement + use<> {
    notes_view("help-page", split(SOURCE).1, state)
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn the_first_heading_is_the_title() {
        assert_eq!(split("# Vault Help\n\nText"), ("Vault Help", "\nText"));
        assert_eq!(split("Text only"), ("Vault Help", "Text only"));
        assert_eq!(split("# Alone"), ("Alone", ""));
    }
}
