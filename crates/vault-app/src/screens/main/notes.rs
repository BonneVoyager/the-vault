//! Notes fields in read mode (owner-approved 2026-10-31): the stored text rendered as GFM
//! Markdown with gpui-component's `TextView`. The editor keeps the raw text, and the
//! notes row's Copy button copies it unchanged.
//!
//! Safety rules (a note comes from the vault, which may come from anywhere):
//! - **Images never load.** Every image (`![alt](url)`, reference images) renders as its
//!   alt text, and the view's image resolver returns a source that never loads, so no
//!   `http(s)`, `file://` or relative path is ever fetched or read.
//! - **Raw HTML is never interpreted.** A block holding any raw HTML renders as its
//!   literal Markdown source. The renderer would otherwise turn `<b>x</b>` into bold
//!   before any plugin sees it, and parse block HTML.
//! - **Links** to `http`/`https` render as link-coloured text with the target in a
//!   tooltip; a click goes through `AppState::open_link`, the Website field's "Open in
//!   browser" path. Any other scheme (`javascript:`, `data:`, `file:`, relative) renders
//!   as plain text and does nothing.
//!
//! Single newlines inside paragraphs stay line breaks, as in GitHub comments
//! ([`hard_breaks`], rendering only).
//!
//! Note text uses the theme foreground, not the muted colour of other field values: the
//! TextView's style has no colour override, and inheriting the row's colour is a switch
//! for every TextView in the app (owner accepted, 2026-10-31).
//!
//! Selection stays on with `SelectionFormat::Source`, so select-all copies the Markdown.
//! The view does not scroll on its own (the detail column scrolls) and inherits the
//! row's text style, so the app's text-size setting applies (`TextViewStyle` has no
//! font size of its own).

use std::sync::atomic::{AtomicUsize, Ordering};

use gpui::{
    App, Entity, InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    StatefulInteractiveElement as _, Styled as _, Window, div,
};
use gpui_component::ActiveTheme as _;
use gpui_component::text::{
    MarkdownNode, MarkdownParseContext, MarkdownPlugin, SelectionFormat, TextView, markdown_ast,
};

use crate::state::AppState;
use crate::ui::Clickable as _;

/// Name of the inline plugin's nodes (images as alt text, links).
const INLINE: &str = "vault-note-inline";
/// Name of blocks shown as their literal source (they hold raw HTML).
const LITERAL: &str = "vault-note-literal";

/// Times the image resolver was asked for a source. It never should be: every image is
/// replaced by its alt text before rendering. Tests assert it stays 0.
pub static IMAGE_RESOLVES: AtomicUsize = AtomicUsize::new(0);

/// The read-mode view of a notes value.
pub fn notes_view(
    id: impl Into<gpui::ElementId>,
    source: &str,
    state: &Entity<AppState>,
) -> TextView {
    let link_state = state.clone();
    TextView::markdown(id, hard_breaks(source))
        .selectable(true)
        .selection_format(SelectionFormat::Source)
        .scrollable(false)
        // Defence in depth: nothing ever loads, whatever reaches the resolver.
        .image_source(|_uri| {
            IMAGE_RESOLVES.fetch_add(1, Ordering::SeqCst);
            gpui::ImageSource::Custom(std::sync::Arc::new(|_, _| None))
        })
        .markdown_block_parser(|node, cx| {
            contains_html(node).then(|| {
                let source = cx.node_source(node).unwrap_or_default().to_owned();
                MarkdownNode::new(LITERAL, ()).text(source)
            })
        })
        .markdown_block_renderer(LITERAL, |node, _, _| {
            let text = node.as_text().to_owned();
            let selector = format!("note-literal {text}");
            div()
                .debug_selector(move || selector.clone())
                .whitespace_normal()
                .child(text)
        })
        .plugin(Inline {
            state: state.clone(),
        })
        // Links the plugin does not claim (none expected): the same rules.
        .on_link_click(move |href, _, _, cx| {
            if is_web_link(href) {
                let href = href.to_string();
                link_state.update(cx, |s, cx| s.open_link(&href, cx));
            }
        })
}

/// The source to render: every single newline inside paragraph text becomes a hard line
/// break (two trailing spaces), as GitHub comments do, so a note written as lines keeps
/// its lines ("PIN 1234\nDoor 5678" is two lines, not one). Code (fenced or indented),
/// table rows, headings, blank lines, and lines followed by the start of another block
/// (list item, heading, quote, fence, table, rule) are left alone, so lists, tables and
/// paragraph breaks parse as before.
///
/// Rendering only: the stored text and the Copy button are unchanged. Select-all in the
/// rendered note (`SelectionFormat::Source`) copies this source, which differs from the
/// stored text only by those invisible trailing spaces. Accepted (owner, 2026-10-31).
pub fn hard_breaks(source: &str) -> String {
    // CRLF and lone CR become LF first (rendering copy only): otherwise the added spaces
    // would land after the CR and every line would render as its own paragraph.
    let source = source.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = source.split('\n').collect();
    let mut out = String::with_capacity(source.len() + source.len() / 8);
    let mut fence: Option<(char, usize)> = None;
    let mut indented_code = false;
    let mut previous_blank = true;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let blank = trimmed.is_empty();
        let opens = fence_marker(line);
        let in_code = if let Some((ch, len)) = fence {
            // Inside a fence until a closing fence of the same character, as long.
            if opens.is_some_and(|(c, l)| {
                c == ch && l >= len && line.trim_end().trim_start().chars().all(|x| x == ch)
            }) {
                fence = None;
            }
            true
        } else if let Some(open) = opens {
            fence = Some(open);
            true
        } else {
            // An indented code block starts after a blank line and runs while lines
            // stay indented (or blank).
            let indented = line.starts_with("    ") || line.starts_with('\t');
            indented_code = indented && (previous_blank || indented_code) || indented_code && blank;
            indented_code
        };
        out.push_str(line);
        let next = lines.get(i + 1).copied();
        let breaks = !in_code
            && !blank
            && !is_table_row(trimmed)
            && !trimmed.starts_with('#')
            && !line.ends_with("  ")
            && !line.ends_with('\\')
            && next.is_some_and(|next| continues_paragraph(trimmed, next));
        if breaks {
            out.push_str("  ");
        }
        if i + 1 < lines.len() {
            out.push('\n');
        }
        previous_blank = blank;
    }
    out
}

/// A fence opener or closer (``` or ~~~, at least three, up to three spaces indent):
/// its character and length.
fn fence_marker(line: &str) -> Option<(char, usize)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let t = &line[indent..];
    let ch = t.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let len = t.chars().take_while(|c| *c == ch).count();
    (len >= 3).then_some((ch, len))
}

fn is_table_row(trimmed: &str) -> bool {
    trimmed.contains('|')
}

/// Whether `next` continues the paragraph `current` belongs to (so a break between
/// them is a soft one to harden), rather than starting another block.
fn continues_paragraph(current: &str, next: &str) -> bool {
    let n = next.trim_start();
    if n.is_empty() || next.starts_with("    ") || next.starts_with('\t') {
        return false;
    }
    // Raw HTML (shown as its literal source anyway) is left exactly as written.
    if current.starts_with('<') || n.starts_with('<') {
        return false;
    }
    // A quote line continuing a quote keeps its line break too.
    if n.starts_with('>') {
        return current.starts_with('>');
    }
    let starts_block = n.starts_with('#')
        || n.starts_with("```")
        || n.starts_with("~~~")
        || is_table_row(n)
        || is_list_item(n)
        || is_rule_or_underline(n);
    !starts_block
}

/// `- x`, `* x`, `+ x`, `1. x`, `1) x`.
fn is_list_item(t: &str) -> bool {
    let mut chars = t.chars();
    match chars.next() {
        Some('-' | '*' | '+') => matches!(chars.next(), Some(' ' | '\t') | None),
        Some(c) if c.is_ascii_digit() => {
            let rest = t.trim_start_matches(|c: char| c.is_ascii_digit());
            (rest.starts_with(". ") || rest.starts_with(") ")) && t.len() - rest.len() <= 9
        }
        _ => false,
    }
}

/// A thematic break (`---`, `***`, `___`) or setext underline (`===`, `---`).
fn is_rule_or_underline(t: &str) -> bool {
    let t = t.trim_end();
    let Some(c) = t.chars().next() else {
        return false;
    };
    matches!(c, '-' | '*' | '_' | '=')
        && t.chars().filter(|x| !x.is_whitespace()).all(|x| x == c)
        && t.chars().filter(|x| *x == c).count() >= if c == '=' { 1 } else { 3 }
}

/// True when `node` or anything below it is raw HTML.
fn contains_html(node: &markdown_ast::Node) -> bool {
    matches!(node, markdown_ast::Node::Html(_))
        || node
            .children()
            .is_some_and(|children| children.iter().any(contains_html))
}

/// An explicit `http://` or `https://` URL (ASCII case-insensitive scheme).
pub fn is_web_link(href: &str) -> bool {
    let href = href.trim();
    let lower = href.get(..8).unwrap_or(href).to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// What an inline node the plugin claimed renders as.
enum Shown {
    /// Plain text: an image's alt text, or a link that will not be opened.
    Text,
    /// A web link to this URL.
    Link(SharedString),
}

struct Inline {
    state: Entity<AppState>,
}

impl MarkdownPlugin for Inline {
    fn name(&self) -> &str {
        INLINE
    }

    fn parse(
        &self,
        node: &markdown_ast::Node,
        _: &MarkdownParseContext<'_>,
    ) -> Option<MarkdownNode> {
        use markdown_ast::Node;
        let (shown, text) = match node {
            Node::Image(i) => (Shown::Text, i.alt.clone()),
            Node::ImageReference(i) => (Shown::Text, i.alt.clone()),
            Node::Link(l) if is_web_link(&l.url) => {
                (Shown::Link(l.url.clone().into()), node.to_string())
            }
            Node::Link(_) | Node::LinkReference(_) => (Shown::Text, node.to_string()),
            _ => return None,
        };
        // An empty text would be replaced by the node's source; a space shows nothing.
        let text = if text.is_empty() {
            " ".to_owned()
        } else {
            text
        };
        Some(MarkdownNode::new(INLINE, shown).text(text))
    }

    fn render(&self, node: &MarkdownNode, _: &mut Window, cx: &mut App) -> impl IntoElement {
        let text = node.as_text().to_owned();
        match node.data::<Shown>() {
            Some(Shown::Link(url)) => {
                let (url, state) = (url.clone(), self.state.clone());
                let tip = url.clone();
                let selector = format!("note-link {url}");
                // The same URL can appear twice: its source offset keeps ids unique.
                let at = node.source_range().map_or(0, |r| r.start);
                let id = SharedString::from(format!("note-link-{at}-{url}"));
                div()
                    .id(id)
                    .debug_selector(move || selector.clone())
                    .text_color(cx.theme().link)
                    .clickable()
                    .tooltip(move |window, cx| {
                        gpui_component::tooltip::Tooltip::new(tip.clone()).build(window, cx)
                    })
                    .on_click(move |_, _, cx| {
                        state.update(cx, |s, cx| s.open_link(&url, cx));
                    })
                    .child(text)
                    .into_any_element()
            }
            _ => {
                let selector = format!("note-text {text}");
                div()
                    .debug_selector(move || selector.clone())
                    .child(text)
                    .into_any_element()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hard_breaks;

    #[test]
    fn single_newlines_become_hard_breaks_in_paragraphs() {
        assert_eq!(hard_breaks("PIN 1234\nDoor 5678"), "PIN 1234  \nDoor 5678");
        // Paragraph breaks and the last line are untouched.
        assert_eq!(hard_breaks("a\n\nb"), "a\n\nb");
        assert_eq!(hard_breaks("a\nb\n"), "a  \nb\n");
        // Already hard: unchanged.
        assert_eq!(hard_breaks("a  \nb"), "a  \nb");
        assert_eq!(hard_breaks("a\\\nb"), "a\\\nb");
        // Quotes keep their lines.
        assert_eq!(hard_breaks("> a\n> b"), "> a  \n> b");
    }

    #[test]
    fn code_tables_lists_and_headings_are_untouched() {
        let fenced = "```\nline one\nline two\n```\nafter";
        assert_eq!(hard_breaks(fenced), fenced);
        let tilde = "~~~~\nx\n~~~\ny\n~~~~";
        assert_eq!(hard_breaks(tilde), tilde, "a shorter fence does not close");
        let indented = "text\n\n    code one\n    code two\n\nmore";
        assert_eq!(hard_breaks(indented), indented);
        let table = "| a | b |\n|---|---|\n| 1 | 2 |";
        assert_eq!(hard_breaks(table), table);
        let list = "- one\n- two\n1. three\n2) four";
        assert_eq!(hard_breaks(list), list);
        // A line before a new block is not given a break.
        assert_eq!(hard_breaks("intro\n- item"), "intro\n- item");
        assert_eq!(hard_breaks("Title\n==="), "Title\n===");
        assert_eq!(hard_breaks("# H\ntext"), "# H\ntext");
        assert_eq!(hard_breaks("text\n---"), "text\n---");
        // CRLF and lone CR are normalised; a CRLF fence stays untouched otherwise.
        assert_eq!(
            hard_breaks("PIN 1234\r\nDoor 5678"),
            "PIN 1234  \nDoor 5678"
        );
        assert_eq!(hard_breaks("a\rb"), "a  \nb");
        assert_eq!(hard_breaks("```\r\nx\r\ny\r\n```"), "```\nx\ny\n```");
        // Raw HTML lines are left as written.
        let html = "<div>\nhi\n</div>";
        assert_eq!(hard_breaks(html), html);
        // A list item's continuation line keeps its break.
        assert_eq!(hard_breaks("- one\n  more"), "- one  \n  more");
    }
}
