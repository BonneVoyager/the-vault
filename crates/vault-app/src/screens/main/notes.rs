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
//! Reference links (`[text][ref]`, `[text][]`, `[text]` with a `[ref]: url` line) to
//! `http`/`https` are rewritten to inline links in the rendering copy
//! ([`resolve_references`]), since the renderer resolves references only while
//! painting, out of the plugin's reach. Other references stay plain text.
//!
//! Note text uses the theme foreground, not the muted colour of other field values: the
//! TextView's style has no colour override, and inheriting the row's colour is a switch
//! for every TextView in the app (owner accepted, 2026-10-31).
//!
//! Selection stays on with `SelectionFormat::Source`, so select-all copies the Markdown.
//! The view does not scroll on its own (the detail column scrolls) and inherits the
//! row's text style, so the app's text-size setting applies (`TextViewStyle` has no
//! font size of its own).

use std::collections::{HashMap, HashSet};
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
    TextView::markdown(id, resolve_references(&hard_breaks(source)))
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
    let code = code_lines(&lines);
    let mut out = String::with_capacity(source.len() + source.len() / 8);
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let blank = trimmed.is_empty();
        let in_code = code[i];
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
    }
    out
}

/// For each line, whether it is code: inside a fence (fence lines included) or an
/// indented code block.
fn code_lines(lines: &[&str]) -> Vec<bool> {
    let mut code = CodeState::new();
    lines.iter().map(|line| code.step(line)).collect()
}

/// Fence and indented-code state, one line at a time.
struct CodeState {
    fence: Option<(char, usize)>,
    indented_code: bool,
    previous_blank: bool,
}

impl CodeState {
    fn new() -> Self {
        Self {
            fence: None,
            indented_code: false,
            previous_blank: true,
        }
    }

    /// Whether `line` is code, advancing the state past it.
    fn step(&mut self, line: &str) -> bool {
        let blank = line.trim_start().is_empty();
        let opens = fence_marker(line);
        let in_code = if let Some((ch, len)) = self.fence {
            // Inside a fence until a closing fence of the same character, as long.
            if opens.is_some_and(|(c, l)| {
                c == ch && l >= len && line.trim_end().trim_start().chars().all(|x| x == ch)
            }) {
                self.fence = None;
            }
            true
        } else if let Some(open) = opens {
            self.fence = Some(open);
            true
        } else {
            // An indented code block starts after a blank line and runs while lines
            // stay indented (or blank).
            let indented = line.starts_with("    ") || line.starts_with('\t');
            self.indented_code = indented && (self.previous_blank || self.indented_code)
                || self.indented_code && blank;
            self.indented_code
        };
        self.previous_blank = blank;
        in_code
    }

    /// Passes over a line that belongs to an HTML block: no fence opens or closes in it.
    fn skip(&mut self, line: &str) {
        self.indented_code = false;
        self.previous_blank = line.trim_start().is_empty();
    }
}

/// The source to render with every reference link whose definition targets `http(s)`
/// rewritten to an inline link: `[text][ref]`, `[text][]` and `[text]` become
/// `[text](url)`, so the inline plugin shows them as web links.
///
/// Definitions are `[label]: url` lines (optional title) outside code and HTML blocks,
/// where CommonMark allows one: at the start of the note or after a blank line, another
/// definition, code, a heading or a rule (a line inside a paragraph is not one). The
/// first definition of a label wins. Labels match after trimming, collapsing whitespace
/// and lower-casing. Everything else is left exactly as written: references to other
/// schemes or to no definition (plain text through the plugin), image references
/// (never loaded), code spans (across lines too) and code blocks, inline link
/// destinations and titles, autolinks, escaped brackets, the definition lines (the
/// parser hides them), and every paragraph holding raw HTML (shown as its literal
/// source).
///
/// Linear in the note's length: the view is rebuilt on every render.
pub fn resolve_references(source: &str) -> String {
    let lines: Vec<&str> = source.split('\n').collect();
    let kinds = line_kinds(&lines);
    let mut definitions: HashMap<String, &str> = HashMap::new();
    for (line, kind) in lines.iter().zip(&kinds) {
        if *kind == LineKind::Definition
            && let Some((label, destination)) = parse_definition(line)
        {
            definitions.entry(label).or_insert(destination);
        }
    }
    definitions.retain(|_, d| is_web_link(d.trim_start_matches('<')));
    if definitions.is_empty() {
        return source.to_owned();
    }
    let mut out = String::with_capacity(source.len() + source.len() / 4);
    // Byte offset of each line's start.
    let mut starts = Vec::with_capacity(lines.len() + 1);
    let mut at = 0;
    for line in &lines {
        starts.push(at);
        at += line.len() + 1;
    }
    starts.push(at);
    let lists = list_units(&lines);
    // Chunks: the lines of one paragraph-like block (text, or text and HTML), with
    // their rewrite (`None` when they hold HTML) and the list they belong to.
    let mut chunks: Vec<(usize, usize, Option<String>, Option<usize>)> = Vec::new();
    let mut html_lists = HashSet::new();
    let mut i = 0;
    while i < lines.len() {
        let mut j = i;
        while j < lines.len() {
            match kinds[j] {
                LineKind::Text | LineKind::Html => j += 1,
                LineKind::HtmlClosed => {
                    j += 1;
                    break;
                }
                _ => break,
            }
        }
        if j == i {
            i += 1;
            continue;
        }
        let chunk = &source[starts[i]..starts[j] - 1];
        let html = kinds[i..j]
            .iter()
            .any(|k| matches!(k, LineKind::Html | LineKind::HtmlClosed));
        let table = lines[i..j].iter().any(|l| is_table_row(l));
        let rewritten = if html {
            None
        } else {
            rewrite_chunk(chunk, table, &definitions)
        };
        let list = lists[i..j].iter().find_map(|l| *l);
        if let Some(list) = list
            && rewritten.is_none()
        {
            html_lists.insert(list);
        }
        chunks.push((i, j, rewritten, list));
        i = j;
    }
    // The block parser sees a whole list at once: one item with HTML shows the whole
    // list as its source, so every chunk of that list stays as written.
    let mut next = 0;
    for (i, j, rewritten, list) in chunks {
        out.push_str(&source[starts[next].min(source.len())..starts[i]]);
        let chunk = &source[starts[i]..starts[j] - 1];
        match rewritten {
            Some(r) if !list.is_some_and(|l| html_lists.contains(&l)) => out.push_str(&r),
            _ => out.push_str(chunk),
        }
        next = j;
        if j < lines.len() {
            out.push('\n');
        }
    }
    if next < lines.len() {
        out.push_str(&source[starts[next]..]);
    }
    out
}

/// For each line, the list it belongs to: a list runs from an item line through
/// further items, indented continuation lines, lazy continuation lines and the blank
/// lines between them, to a non-indented, non-item line after a blank line.
fn list_units(lines: &[&str]) -> Vec<Option<usize>> {
    let mut current: Option<usize> = None;
    let mut count = 0;
    let mut previous_blank = true;
    lines
        .iter()
        .map(|line| {
            let blank = line.trim().is_empty();
            let indent = line.len() - line.trim_start_matches(' ').len();
            let item = indent <= 3 && is_list_item(line.trim_start());
            if current.is_some()
                && !(blank || item || !previous_blank || line.starts_with([' ', '\t']))
            {
                current = None;
            }
            if current.is_none() && item {
                count += 1;
                current = Some(count);
            }
            previous_blank = blank;
            current
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LineKind {
    Blank,
    Code,
    Html,
    /// The line ending an HTML block of kinds 1-5: the next line starts a new block.
    HtmlClosed,
    Definition,
    Text,
}

/// What each line is, for finding definitions and the chunks to rewrite.
fn line_kinds(lines: &[&str]) -> Vec<LineKind> {
    // Fences are tracked here, not with `code_lines`: a fence marker inside an HTML
    // block is HTML, not a fence.
    let mut code = CodeState::new();
    // The open HTML block's end: `None` outside one.
    let mut in_html: Option<HtmlEnd> = None;
    // Whether a definition may start here (no paragraph to continue).
    let mut may_start = true;
    // Whether the previous line was paragraph text (a `===` under it is an underline).
    let mut previous_text = false;
    let mut kinds = Vec::with_capacity(lines.len());
    for line in lines {
        let t = line.trim();
        let kind = if let Some(end) = in_html {
            code.skip(line);
            if end == HtmlEnd::BlankLine {
                // Kinds 6 and 7 run to a blank line.
                if t.is_empty() {
                    in_html = None;
                    LineKind::Blank
                } else {
                    LineKind::Html
                }
            } else if end.found_in(line) {
                // Kinds 1-5 run to their end marker, blank lines and fences included.
                in_html = None;
                LineKind::HtmlClosed
            } else {
                LineKind::Html
            }
        } else if code.step(line) {
            LineKind::Code
        } else if t.is_empty() {
            LineKind::Blank
        } else if let Some((end, rest)) = html_block_start(line) {
            if end.found_in(rest) {
                LineKind::HtmlClosed
            } else {
                in_html = Some(end);
                LineKind::Html
            }
        } else if may_start && parse_definition(line).is_some() {
            LineKind::Definition
        } else {
            LineKind::Text
        };
        let ends_block =
            is_atx_heading(t) || is_rule_or_underline(t) && (!t.starts_with('=') || previous_text);
        may_start = match kind {
            LineKind::Blank | LineKind::Code | LineKind::Definition | LineKind::HtmlClosed => true,
            LineKind::Html => false,
            LineKind::Text => ends_block,
        };
        previous_text = kind == LineKind::Text && !ends_block;
        kinds.push(kind);
    }
    kinds
}

/// Where an HTML block ends (CommonMark kinds 1-5 end at a marker, 6-7 at a blank line).
#[derive(Clone, Copy, PartialEq, Eq)]
enum HtmlEnd {
    /// 1: `</pre>`, `</script>`, `</style>` or `</textarea>`, any case.
    RawTag,
    /// 2: `-->`.
    Comment,
    /// 3: `?>`.
    Instruction,
    /// 4: `>`.
    Declaration,
    /// 5: `]]>`.
    Cdata,
    /// 6 and 7: a blank line.
    BlankLine,
}

impl HtmlEnd {
    fn found_in(self, line: &str) -> bool {
        match self {
            HtmlEnd::RawTag => {
                let lower = line.to_ascii_lowercase();
                ["</pre>", "</script>", "</style>", "</textarea>"]
                    .iter()
                    .any(|t| lower.contains(t))
            }
            HtmlEnd::Comment => line.contains("-->"),
            HtmlEnd::Instruction => line.contains("?>"),
            HtmlEnd::Declaration => line.contains('>'),
            HtmlEnd::Cdata => line.contains("]]>"),
            HtmlEnd::BlankLine => false,
        }
    }
}

/// An HTML block start (up to three spaces, then `<` and a tag, `</tag`, `<!` or
/// `<?`): how it ends, and the rest of the line after the opener, where a kind 1-5
/// block may already end.
fn html_block_start(line: &str) -> Option<(HtmlEnd, &str)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    let after = line.get(indent..)?.strip_prefix('<')?;
    if indent > 3 || !is_tag_start(after) {
        return None;
    }
    // The first characters, lower-cased (a byte prefix could split a character).
    let lower = after
        .chars()
        .take(9)
        .collect::<String>()
        .to_ascii_lowercase();
    let raw = ["pre", "script", "style", "textarea"].iter().find(|t| {
        lower.starts_with(*t)
            && after[t.len()..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace() || c == '>')
    });
    let (end, opener) = if let Some(t) = raw {
        (HtmlEnd::RawTag, t.len())
    } else if after.starts_with("!--") {
        (HtmlEnd::Comment, 3)
    } else if after.starts_with('?') {
        (HtmlEnd::Instruction, 1)
    } else if after.starts_with("![CDATA[") {
        (HtmlEnd::Cdata, 8)
    } else if after.starts_with('!') && after[1..].starts_with(|c: char| c.is_ascii_alphabetic()) {
        (HtmlEnd::Declaration, 1)
    } else {
        (HtmlEnd::BlankLine, 0)
    };
    Some((end, &after[opener..]))
}

/// Whether `s`, the text after a `<`, starts a tag (`a`, `/a`, followed by a space,
/// `>`, `/` or the end), a comment or declaration (`!`), or a processing
/// instruction (`?`). Autolinks (`<https://…>`, `<a@b.c>`) are not tags.
fn is_tag_start(s: &str) -> bool {
    let s = s.strip_prefix('/').unwrap_or(s);
    if s.starts_with(['!', '?']) {
        return true;
    }
    let mut chars = s.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let rest = chars.as_str();
    let name = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(rest.len());
    rest[name..]
        .chars()
        .next()
        .is_none_or(|c| c.is_whitespace() || c == '>' || c == '/')
}

/// `# Heading` (one to six `#`, then a space or the end of the line).
fn is_atx_heading(t: &str) -> bool {
    let hashes = t.chars().take_while(|c| *c == '#').count();
    (1..=6).contains(&hashes) && t[hashes..].chars().next().is_none_or(char::is_whitespace)
}

/// `[label]: destination ["title"]` on one line, up to three spaces indent: the
/// normalised label and the destination as written (`<...>` form included).
fn parse_definition(line: &str) -> Option<(String, &str)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = line[indent..].strip_prefix('[')?;
    let close = label_end(rest)?;
    let label = normalize_label(&rest[..close])?;
    let rest = rest[close + 1..].strip_prefix(':')?.trim_start();
    let (destination, after) = if rest.starts_with('<') {
        let end = rest.find('>')? + 1;
        (&rest[..end], &rest[end..])
    } else {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        (&rest[..end], &rest[end..])
    };
    if destination.is_empty() {
        return None;
    }
    let title = after.trim();
    let title_ok = title.is_empty()
        || after.starts_with(char::is_whitespace)
            && title.len() >= 2
            && matches!(
                (title.chars().next(), title.chars().last()),
                (Some('"'), Some('"')) | (Some('\''), Some('\'')) | (Some('('), Some(')'))
            );
    title_ok.then_some((label, destination))
}

/// Longest link label, in bytes (CommonMark: 999 characters).
const MAX_LABEL: usize = 999;

/// Index of the `]` closing a label that starts right after a `[`: no unescaped
/// brackets inside, at most [`MAX_LABEL`] bytes. Stops at the first bracket, so a
/// scan never passes the next one.
fn label_end(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if i > MAX_LABEL {
            return None;
        }
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '[' => return None,
            ']' => return Some(i),
            _ => {}
        }
    }
    None
}

/// CommonMark label matching: trimmed, inner whitespace collapsed, case-folded. `None`
/// for a blank label.
fn normalize_label(label: &str) -> Option<String> {
    let words: Vec<&str> = label.split_whitespace().collect();
    (!words.is_empty()).then(|| words.join(" ").to_lowercase())
}

/// An open `[` (or the `[` of `![`) waiting for its `]`.
struct Opener {
    at: usize,
    image: bool,
    /// Another `[` opened inside it: its text is no valid label.
    nested: bool,
}

/// `chunk` (one paragraph-like block, newlines included) with web reference links
/// rewritten, or `None` to keep it as written (it holds inline HTML). One left-to-right
/// pass: brackets go on a stack, code spans and inline link destinations are skipped
/// through tables built once, so no byte is scanned more than a bounded number of times.
fn rewrite_chunk(chunk: &str, table: bool, definitions: &HashMap<String, &str>) -> Option<String> {
    let b = chunk.as_bytes();
    let runs = BacktickRuns::new(b);
    let parens = Parens::new(b);
    let last_gt = chunk.rfind('>');
    let lookup = |label: &str| {
        let d = *definitions.get(&normalize_label(label)?)?;
        // A `|` would split a table cell: such a link stays as written.
        (!(table && d.contains('|'))).then_some(d)
    };
    let mut out = String::new();
    let mut copied = 0;
    let mut stack: Vec<Opener> = Vec::new();
    // Link openers below this depth are inactive: links do not nest.
    let mut floor = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1).is_some_and(u8::is_ascii_punctuation) => {
                // An escaped backtick is literal, but the rest of its run can still
                // open a code span: the run is left to the backtick arm.
                i += if b[i + 1] == b'`' { 1 } else { 2 };
            }
            b'`' => i = runs.skip(i),
            b'<' => {
                if is_tag_start(&chunk[i + 1..]) && last_gt.is_some_and(|g| g > i) {
                    return None;
                }
                // An autolink: skip to its `>`. The scan stops at the next `<`, `>`
                // or space, so these scans never overlap.
                let end = b[i + 1..]
                    .iter()
                    .position(|c| matches!(c, b'<' | b'>') || c.is_ascii_whitespace())
                    .map(|p| i + 1 + p);
                i = match end {
                    Some(e) if b[e] == b'>' && chunk[i + 1..e].contains([':', '@']) => e + 1,
                    _ => i + 1,
                };
            }
            b'[' => {
                let image = i > 0 && b[i - 1] == b'!' && !escaped_at(b, i - 1);
                if let Some(top) = stack.last_mut() {
                    top.nested = true;
                }
                stack.push(Opener {
                    at: i,
                    image,
                    nested: false,
                });
                i += 1;
            }
            b']' => {
                let Some(opener) = stack.pop() else {
                    i += 1;
                    continue;
                };
                // Its depth is `stack.len()` now: below the floor, it is inactive.
                let inactive = !opener.image && stack.len() < floor;
                floor = floor.min(stack.len());
                let after = i + 1;
                if b.get(after) == Some(&b'(') {
                    // An inline link or image: skip its destination and title.
                    i = parens.close_of(after).map_or(after, |c| c + 1);
                    if !opener.image {
                        floor = stack.len();
                    }
                    continue;
                }
                if opener.image || inactive {
                    // An image's label is skipped too (it never loads); an inactive
                    // opener inside a link is plain text.
                    i = after;
                    if opener.image && b.get(after) == Some(&b'[') {
                        i = label_end(&chunk[after + 1..]).map_or(after, |e| after + 2 + e);
                    }
                    continue;
                }
                let text = &chunk[opener.at + 1..i];
                let shortcut = (!opener.nested && text.len() <= MAX_LABEL).then_some(text);
                let (label, end) = match b.get(after) {
                    Some(b'[') => match label_end(&chunk[after + 1..]) {
                        Some(0) => (shortcut, after + 2),
                        Some(len) => (Some(&chunk[after + 1..after + 1 + len]), after + 2 + len),
                        None => (shortcut, after),
                    },
                    _ => (shortcut, after),
                };
                if let Some(destination) = label.and_then(lookup) {
                    out.push_str(&chunk[copied..after]);
                    out.push('(');
                    out.push_str(destination);
                    out.push(')');
                    copied = end;
                    floor = stack.len();
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    out.push_str(&chunk[copied..]);
    Some(out)
}

/// Whether the byte at `at` is backslash-escaped. Counts the run of backslashes
/// right before it; callers ask at most once per backtick run or `![`, so each run of
/// backslashes is counted at most twice.
fn escaped_at(b: &[u8], at: usize) -> bool {
    b[..at].iter().rev().take_while(|c| **c == b'\\').count() % 2 == 1
}

/// The backtick runs of a chunk and, for each, the next run that closes a code span it
/// opens, built in one pass from the right. A run whose first backtick is escaped opens
/// with the rest of its run only (it still closes with all of it: inside a code span a
/// backslash is literal).
struct BacktickRuns {
    runs: Vec<Run>,
}

struct Run {
    start: usize,
    len: usize,
    escaped: bool,
    /// Index of the run closing the code span this one opens.
    close: Option<usize>,
}

impl Run {
    /// Length of the run as an opener.
    fn open_len(&self) -> usize {
        self.len - usize::from(self.escaped)
    }
}

impl BacktickRuns {
    fn new(b: &[u8]) -> Self {
        let mut runs = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'`' {
                let len = b[i..].iter().take_while(|c| **c == b'`').count();
                runs.push(Run {
                    start: i,
                    len,
                    escaped: escaped_at(b, i),
                    close: None,
                });
                i += len;
            } else {
                i += 1;
            }
        }
        // Closers by length: the nearest run to the right with exactly that length.
        let mut next: HashMap<usize, usize> = HashMap::new();
        for k in (0..runs.len()).rev() {
            let open_len = runs[k].open_len();
            runs[k].close = (open_len > 0)
                .then(|| next.get(&open_len).copied())
                .flatten();
            next.insert(runs[k].len, k);
        }
        Self { runs }
    }

    /// Where scanning resumes after the backtick run at `at`: past the code span it
    /// opens, or past the run itself when nothing closes it.
    fn skip(&self, at: usize) -> usize {
        let Ok(k) = self.runs.binary_search_by_key(&at, |r| r.start) else {
            return at + 1;
        };
        let run = &self.runs[k];
        match run.close {
            Some(close) => self.runs[close].start + self.runs[close].len,
            None => at + run.len,
        }
    }
}

/// Matching parentheses of a chunk (escaped ones ignored), built in one pass.
struct Parens {
    /// (open, close) pairs, sorted by open.
    pairs: Vec<(usize, usize)>,
    /// Unescaped `)` positions, sorted.
    closes: Vec<usize>,
}

impl Parens {
    fn new(b: &[u8]) -> Self {
        let (mut pairs, mut closes, mut open) = (Vec::new(), Vec::new(), Vec::new());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 1,
                b'(' => open.push(i),
                b')' => {
                    closes.push(i);
                    if let Some(o) = open.pop() {
                        pairs.push((o, i));
                    }
                }
                _ => {}
            }
            i += 1;
        }
        pairs.sort_unstable();
        Self { pairs, closes }
    }

    /// The `)` ending the inline link whose `(` is at `open`: its match, or the next
    /// `)` when it has none (an unbalanced destination or title).
    fn close_of(&self, open: usize) -> Option<usize> {
        if let Ok(k) = self.pairs.binary_search_by_key(&open, |p| p.0) {
            return Some(self.pairs[k].1);
        }
        let k = self.closes.partition_point(|c| *c < open);
        self.closes.get(k).copied()
    }
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
    use super::{hard_breaks, resolve_references as resolve};

    const DEFS: &str =
        "\n\n[ref]: https://example.org\n[Mail]: mailto:a@b.c\n[img]: https://x.invalid/p.png";

    /// `note` with the definitions appended, resolved, and the definitions cut off again.
    fn body(note: &str) -> String {
        let out = resolve(&format!("{note}{DEFS}"));
        out.strip_suffix(DEFS)
            .expect("definitions untouched")
            .to_owned()
    }

    #[test]
    fn web_references_become_inline_links() {
        assert_eq!(body("[text][ref]"), "[text](https://example.org)");
        assert_eq!(body("[ref][]"), "[ref](https://example.org)");
        assert_eq!(
            body("see [ref] here"),
            "see [ref](https://example.org) here"
        );
        // Labels match case-insensitively, with whitespace collapsed.
        assert_eq!(body("[t][ REF ]"), "[t](https://example.org)");
        assert_eq!(body("[REF]"), "[REF](https://example.org)");
        let spaced = resolve("[a b]\n\n[A   b]: <https://x.y/a b>");
        assert_eq!(
            spaced,
            "[a b](<https://x.y/a b>)\n\n[A   b]: <https://x.y/a b>"
        );
        // A title is allowed and the first definition wins.
        let titled = "[x]\n\n[x]: https://one.org \"One\"\n[x]: https://two.org";
        assert_eq!(
            resolve(titled),
            titled.replacen("[x]\n", "[x](https://one.org)\n", 1)
        );
        // An unclosed backtick is literal, so the reference after it is real.
        assert_eq!(
            body("unclosed ` [ref]"),
            "unclosed ` [ref](https://example.org)"
        );
        // Several on one line, around inline links.
        assert_eq!(
            body("[a](https://i.org) [b][ref] [ref]"),
            "[a](https://i.org) [b](https://example.org) [ref](https://example.org)"
        );
    }

    #[test]
    fn other_references_stay_as_written() {
        for note in [
            "[mail][mail]",    // mailto: target
            "[Mail]",          // shortcut to mailto:
            "[text]",          // undefined shortcut: ordinary brackets
            "[text][nope]",    // undefined label
            "![logo][img]",    // image reference: never loads
            "![img]",          // shortcut image
            "![alt][ref]",     // image to a web URL
            "`[text][ref]`",   // code span
            "``a ` [ref] b``", // code span with a backtick inside
            "\\[ref]",         // escaped bracket
        ] {
            assert_eq!(body(note), note, "{note}");
        }
        // Fenced and indented code.
        let fenced = "```\n[ref]\n```";
        assert_eq!(body(fenced), fenced);
        let indented = "text\n\n    [ref]";
        assert_eq!(body(indented), indented);
        // A definition line inside a paragraph is not a definition.
        let inside = "[x]\ntext\n[x]: https://example.org";
        assert_eq!(resolve(inside), inside);
        // Inside code, a definition is not one either.
        let code_def = "[x]\n\n```\n[x]: https://example.org\n```";
        assert_eq!(resolve(code_def), code_def);
        // No definitions at all: the source as is.
        assert_eq!(resolve("[a] [b][c]"), "[a] [b][c]");
    }

    #[test]
    fn html_code_spans_destinations_and_autolinks_stay_as_written() {
        for note in [
            // HTML blocks and paragraphs holding inline HTML render as their source.
            "<div>\n[ref]\n</div>",
            "<!-- [ref] -->",
            "see <span>[ref]</span>",
            "[ref] and\n<b>bold</b>",
            // A code span running over several lines.
            "a `code\n[ref]` b",
            "a ``x ` [ref]\n[ref]`` b",
            // Inline link destinations and titles, autolinks.
            "[a](https://x.org/[ref])",
            "[a](https://x.org/(p)[ref])",
            "[a](https://x.org \"[ref]\")",
            "![a](https://x.org/[ref].png)",
            "<https://x.org/[ref]>",
        ] {
            assert_eq!(body(note), note, "{note}");
        }
        // Text around HTML-free autolinks and comparisons is still rewritten.
        assert_eq!(
            body("<https://y.org> [ref] a < b"),
            "<https://y.org> [ref](https://example.org) a < b"
        );
        assert_eq!(
            body("`x`\n[ref]"),
            "`x`\n[ref](https://example.org)",
            "a closed code span ends where it closes"
        );
        // Links do not nest: the outer brackets stay text, so `[ref]` is a shortcut.
        assert_eq!(
            body("[a [b](https://x.org) c][ref]"),
            "[a [b](https://x.org) c][ref](https://example.org)"
        );
        // The paragraph after an HTML block is rewritten again.
        assert_eq!(
            body("<div>\n[ref]\n</div>\n\n[ref]"),
            "<div>\n[ref]\n</div>\n\n[ref](https://example.org)"
        );
    }

    #[test]
    fn an_escape_covers_one_backtick_only() {
        // The rest of the run still opens a code span.
        let note = "\\``x [ref] `";
        assert_eq!(body(note), note);
        // Here the rest (one backtick) has no closer: both references are real.
        assert_eq!(
            body("\\`` [ref] `` [ref]"),
            "\\`` [ref](https://example.org) `` [ref](https://example.org)"
        );
    }

    #[test]
    fn html_blocks_run_to_their_end_marker() {
        for note in [
            "<!--\n\n[ref]\n-->",
            "<?\n\n[ref]\n?>",
            "<!DOCTYPE\n\n[ref]\n>",
            "<![CDATA[\n\n[ref]\n]]>",
            "<SCRIPT>\n\n[ref]\n</script>",
            "<textarea>\n```\n\n[ref]\n</textarea>",
        ] {
            assert_eq!(body(note), note, "{note}");
        }
        // After the end marker (same line or later), Markdown resumes.
        assert_eq!(
            body("<pre>\n[ref]\n\n[ref]\n</pre>\n\n[ref]"),
            "<pre>\n[ref]\n\n[ref]\n</pre>\n\n[ref](https://example.org)"
        );
        assert_eq!(
            body("<!-- c -->\n[ref]"),
            "<!-- c -->\n[ref](https://example.org)"
        );
        // A fence marker inside an HTML block is HTML: the real fence after it holds.
        // (The definition comes first: a fence left open must not swallow it.)
        for html in ["<!--\n```\n-->", "<div>\n```\n"] {
            let fenced = format!("[ref]: https://example.org\n\n{html}\n```\n[ref]\n```\n\n[ref]");
            let expected = format!("{}(https://example.org)", fenced);
            assert_eq!(resolve(&fenced), expected, "{html}");
        }
        // A multi-byte character near the tag name does not hide the block.
        let accented = "<div     é\n[ref]";
        assert_eq!(body(accented), accented);
        // Kinds 6 and 7 still end at a blank line.
        assert_eq!(
            body("<div>\n[ref]\n\n[ref]"),
            "<div>\n[ref]\n\n[ref](https://example.org)"
        );
    }

    #[test]
    fn a_list_with_html_in_any_item_stays_as_written() {
        for note in [
            "- [ref]\n\n- <b>x</b>",
            "1. [ref]\n\n   more\n\n2. <b>x</b>",
            "- [ref]\nlazy\n\n  <i>y</i>",
        ] {
            assert_eq!(body(note), note, "{note}");
        }
        assert_eq!(
            body("- [ref]\n\n- b"),
            "- [ref](https://example.org)\n\n- b"
        );
        // The paragraph after the list is its own block.
        assert_eq!(
            body("- <b>x</b>\n\n[ref]"),
            "- <b>x</b>\n\n[ref](https://example.org)"
        );
    }

    #[test]
    fn a_lone_equals_line_does_not_end_a_paragraph() {
        // After a blank line, `=` is paragraph text, so the next line is no definition.
        let note = "[x]\n\n=\n[x]: https://h.org";
        assert_eq!(resolve(note), note);
        // Under paragraph text it is a setext underline, which ends the heading.
        let setext = "[x]\n\nTitle\n=\n[x]: https://h.org";
        assert!(resolve(setext).starts_with("[x](https://h.org)\n"));
    }

    /// The rewrite runs on every render: it must stay linear on hostile input. A
    /// quadratic pass took 3.5 s (release) on the first case; each now takes well under
    /// 200 ms in a debug build, so the generous bound only trips on quadratic work.
    #[test]
    fn the_rewrite_is_linear() {
        let unit = |s: &str| s.repeat(1_000_000 / s.len());
        let cases = [
            unit(&format!("[{}", "x".repeat(99))),
            unit("[a]("),
            unit("![a]["),
            unit("[a][b"),
            unit("<a:"),
            unit("` [ref] "),
            format!("{}{}", "[".repeat(500_000), "]".repeat(500_000)),
            (1..1400).map(|n| "`".repeat(n) + " ").collect(),
        ];
        for case in cases {
            let note = format!("{case}{DEFS}");
            let start = std::time::Instant::now();
            let out = resolve(&note);
            let took = start.elapsed();
            assert!(out.len() >= note.len());
            assert!(
                took < std::time::Duration::from_secs(1),
                "{took:?} for {}",
                &case[..20]
            );
        }
    }

    #[test]
    fn many_definitions_and_references_stay_fast() {
        let refs: String = (0..20_000).map(|n| format!("[t][d{n}] ")).collect();
        let defs: String = (0..20_000)
            .map(|n| format!("\n[D{n}]: https://e.org/{n}"))
            .collect();
        let note = format!("{refs}\n{defs}");
        let start = std::time::Instant::now();
        let out = resolve(&note);
        let took = start.elapsed();
        assert!(out.starts_with("[t](https://e.org/0) [t](https://e.org/1) "));
        assert!(out.contains("[t](https://e.org/19999) "));
        assert!(took < std::time::Duration::from_secs(1), "{took:?}");
    }

    #[test]
    fn definitions_after_headings_and_hard_breaks_still_count() {
        let note = "# Links\n[x]: https://h.org\n[y]: https://i.org\n[x] [y]";
        let out = resolve(&hard_breaks(note));
        assert!(
            out.ends_with("[x](https://h.org) [y](https://i.org)"),
            "{out}"
        );
        // The definition lines (with hard_breaks' trailing spaces) are kept.
        assert!(
            out.contains("[x]: https://h.org  \n[y]: https://i.org"),
            "{out}"
        );
    }

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
