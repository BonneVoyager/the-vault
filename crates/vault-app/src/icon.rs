//! Item icons (specs/05-ui.md §2.3 item list and detail header): what an item's tile shows.
//!
//! Decided here without gpui; `screens::main::icon_view` draws the result.
//! 1. Automatic: the letter avatar (first letter of the title on the item's palette colour).
//! 2. Manual: `Item.icon` (01 §4) with kind `symbol` (a Lucide icon from the full bundled
//!    catalog, stored by its `IconName` identifier, plus an optional colour) or `letter`
//!    (a colour-only choice tinting the letter avatar). The 40 curated [`SYMBOLS`] are what
//!    the picker shows without a query and what field icons may use.
//! 3. Kind `image`: `value` is the id (lowercase hyphenated UUID) of an attachment of the
//!    same item holding a 128 px PNG ([`IconSpec::Image`]). That attachment is hidden from
//!    every attachment list ([`is_icon_attachment`]). A value that is not a UUID resolves to
//!    the automatic icon; a missing or undecodable blob is drawn as the automatic icon too.
//!
//! Kind `logo` (the brand pack, removed 2026-11-16) counts as no icon. Any other kind this
//! build does not know resolves to [`IconSpec::Unsupported`] and draws as the letter
//! avatar. The stored value is never touched, so a newer app's choice survives.

use std::collections::HashMap;
use std::sync::LazyLock;

use gpui_kit_assets::IconName;
use vault_core::{AttachmentRef, Item, ItemIcon, Uuid};

use crate::listing;

/// `Item.icon.kind` values this build writes or reads.
pub const KIND_SYMBOL: &str = "symbol";
/// Written by older builds for a brand logo; read as no icon.
pub const KIND_LOGO: &str = "logo";
pub const KIND_LETTER: &str = "letter";
pub const KIND_IMAGE: &str = "image";

/// Letter-avatar and symbol colours (the picker's swatches); white reads on all of them in
/// both appearances. An item without a chosen colour gets one from its id.
pub const PALETTE: [u32; 8] = [
    0x3B6CF0, 0x30A46C, 0xE5484D, 0xC2790A, 0x8E4EC6, 0x12A594, 0xD6409F, 0xE5622E,
];

/// VoiceOver names of the [`PALETTE`] swatches.
pub const PALETTE_NAMES: [&str; 8] = [
    "Blue", "Green", "Red", "Amber", "Purple", "Teal", "Pink", "Orange",
];

/// The picker's symbols: stored name (the `IconName` variant name), icon, label.
pub const SYMBOLS: [(&str, IconName, &str); 40] = [
    ("Landmark", IconName::Landmark, "Bank"),
    ("CreditCard", IconName::CreditCard, "Credit card"),
    ("Wallet", IconName::Wallet, "Wallet"),
    ("ShoppingCart", IconName::ShoppingCart, "Shopping"),
    ("Gift", IconName::Gift, "Gift"),
    ("Mail", IconName::Mail, "Mail"),
    ("MessageCircle", IconName::MessageCircle, "Message"),
    ("Bell", IconName::Bell, "Bell"),
    ("KeyRound", IconName::KeyRound, "Key"),
    ("Lock", IconName::Lock, "Lock"),
    ("Shield", IconName::Shield, "Shield"),
    ("User", IconName::User, "User"),
    ("Users", IconName::Users, "Users"),
    ("House", IconName::House, "Home"),
    ("Briefcase", IconName::Briefcase, "Work"),
    ("GraduationCap", IconName::GraduationCap, "School"),
    ("Cloud", IconName::Cloud, "Cloud"),
    ("Server", IconName::Server, "Server"),
    ("Database", IconName::Database, "Database"),
    ("Code", IconName::Code, "Code"),
    ("SquareTerminal", IconName::SquareTerminal, "Terminal"),
    ("Bug", IconName::Bug, "Bug"),
    ("Wifi", IconName::Wifi, "Wi-Fi"),
    ("Globe", IconName::Globe, "Globe"),
    ("Smartphone", IconName::Smartphone, "Phone"),
    ("Gamepad2", IconName::Gamepad2, "Game"),
    ("Music", IconName::Music, "Music"),
    ("Film", IconName::Film, "Film"),
    ("Camera", IconName::Camera, "Camera"),
    ("Image", IconName::Image, "Image"),
    ("BookOpen", IconName::BookOpen, "Book"),
    ("Folder", IconName::Folder, "Folder"),
    ("FileText", IconName::FileText, "Document"),
    ("Calendar", IconName::Calendar, "Calendar"),
    ("MapPin", IconName::MapPin, "Place"),
    ("Car", IconName::Car, "Car"),
    ("Plane", IconName::Plane, "Travel"),
    ("Coffee", IconName::Coffee, "Coffee"),
    ("Heart", IconName::Heart, "Heart"),
    ("Star", IconName::Star, "Star"),
];

/// Columns of the picker's symbol and colour grids.
pub const GRID_COLS: usize = 8;

#[cfg(test)]
thread_local! {
    /// Calls of [`search`] on this thread, for the "not per render" test.
    pub static SEARCH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Most results the picker's search shows (05 "Icon search").
pub const SEARCH_CAP: usize = 120;

/// One icon of the bundled Lucide catalog.
struct CatalogIcon {
    icon: IconName,
    /// The `IconName` variant name, the stored form (`"Gamepad2"`).
    id: String,
    /// The kebab-case asset name with hyphens as spaces, lowercase (`"gamepad 2"`).
    words: String,
}

/// The whole catalog in `IconName::ALL` order, and its identifiers, built on first use
/// (about 1,830 short strings).
#[allow(clippy::type_complexity)]
static CATALOG: LazyLock<(
    Vec<CatalogIcon>,
    HashMap<String, usize>,
    HashMap<IconName, usize>,
)> = LazyLock::new(|| {
    let icons: Vec<CatalogIcon> = IconName::ALL
        .iter()
        .map(|&icon| {
            let path = icon.path();
            let kebab = path
                .strip_prefix("icons/")
                .and_then(|p| p.strip_suffix(".svg"))
                .unwrap_or(&path);
            CatalogIcon {
                icon,
                id: format!("{icon:?}"),
                words: kebab.replace('-', " ").to_lowercase(),
            }
        })
        .collect();
    let ids = icons
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.clone(), i))
        .collect();
    let by_icon = icons.iter().enumerate().map(|(i, c)| (c.icon, i)).collect();
    (icons, ids, by_icon)
});

/// No allocation: called for every grid cell's tooltip and label.
fn catalog_entry(icon: IconName) -> Option<&'static CatalogIcon> {
    let (icons, _, by_icon) = &*CATALOG;
    by_icon.get(&icon).map(|&i| &icons[i])
}

/// The picker's search results for `query` (05 "Icon search"), at most [`SEARCH_CAP`]:
/// curated [`SYMBOLS`] whose label, identifier or name contains it, in their order, then
/// catalog icons whose name (kebab-case, hyphens as spaces) contains it, name-prefix
/// matches first, alphabetical within each group. Case-insensitive; hyphens in the query
/// count as spaces. Empty for an empty query (the grid shows [`SYMBOLS`]).
pub fn search(query: &str) -> Vec<PickerCell> {
    #[cfg(test)]
    SEARCH_CALLS.with(|c| c.set(c.get() + 1));
    let q = query.trim().replace('-', " ").to_lowercase();
    if q.is_empty() {
        return Vec::new();
    }
    let curated = SYMBOLS.iter().enumerate().filter(|(_, (id, icon, label))| {
        label.to_lowercase().contains(&q)
            || id.to_lowercase().contains(&q)
            || catalog_entry(*icon).is_some_and(|c| c.words.contains(&q))
    });
    let mut rest: Vec<(bool, &CatalogIcon)> = CATALOG
        .0
        .iter()
        .filter(|c| !SYMBOLS.iter().any(|(_, i, _)| *i == c.icon) && c.words.contains(&q))
        .map(|c| (!c.words.starts_with(&q), c))
        .collect();
    rest.sort_unstable_by(|a, b| (a.0, &a.1.words).cmp(&(b.0, &b.1.words)));
    curated
        .map(|(i, _)| PickerCell::Symbol(i))
        .chain(rest.into_iter().map(|(_, c)| PickerCell::Icon(c.icon)))
        .take(SEARCH_CAP)
        .collect()
}

/// The open picker's search (item and field pickers share it; one is open at a time):
/// the query, its results computed once per change, and the keyboard cursor in them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PickerSearch {
    query: String,
    hits: Vec<PickerCell>,
    hit: Option<usize>,
}

impl PickerSearch {
    /// True while there is a query: the grid shows [`Self::hits`], not [`SYMBOLS`].
    pub fn active(&self) -> bool {
        !self.query.trim().is_empty()
    }

    #[cfg(test)]
    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn hits(&self) -> &[PickerCell] {
        &self.hits
    }

    /// The keyboard cursor's index in [`Self::hits`], if it is in them.
    pub fn hit(&self) -> Option<usize> {
        self.hit
    }

    /// A new query: runs [`search`] once and puts the cursor back in the field. Returns
    /// false (and changes nothing) when the query is unchanged.
    pub fn set_query(&mut self, query: String) -> bool {
        if query == self.query {
            return false;
        }
        self.hits = search(&query);
        self.query = query;
        self.hit = None;
        true
    }

    /// Arrow over the results, [`GRID_COLS`] per row: ↓ (or →) from the field enters
    /// them, ↑ from their first row leaves them, ←/→ stop at the ends.
    pub fn step(&mut self, m: Move) {
        let last = self.hits.len().checked_sub(1);
        self.hit = match (self.hit, m, last) {
            (_, _, None) => None,
            (None, Move::Down | Move::Right, Some(_)) => Some(0),
            (None, ..) => None,
            (Some(i), Move::Up, _) => i.checked_sub(GRID_COLS),
            (Some(i), Move::Down, Some(l)) => Some((i + GRID_COLS).min(l)),
            (Some(i), Move::Left, _) => Some(i.saturating_sub(1)),
            (Some(i), Move::Right, Some(l)) => Some((i + 1).min(l)),
        };
    }

    /// What Enter picks: the result under the cursor, else the first one.
    pub fn chosen(&self) -> Option<PickerCell> {
        self.hits.get(self.hit.unwrap_or(0)).copied()
    }
}

/// The catalog icon behind a search result or grid cell (`Symbol(i)` is [`SYMBOLS`]`[i]`).
pub fn cell_icon(cell: PickerCell) -> Option<IconName> {
    match cell {
        PickerCell::Symbol(i) => SYMBOLS.get(i).map(|(_, icon, _)| *icon),
        PickerCell::Icon(icon) => Some(icon),
        _ => None,
    }
}

/// Display name of a catalog icon outside [`SYMBOLS`]: its words, capitalised
/// (`"Gamepad 2"`).
pub fn catalog_label(icon: IconName) -> String {
    catalog_entry(icon).map_or_else(
        || format!("{icon:?}"),
        |c| crate::text::capitalize_first(&c.words),
    )
}

/// What an item's tile shows.
#[derive(Debug, Clone, PartialEq)]
pub enum IconSpec {
    /// Letter avatar: first letter of the title on `color`.
    Letter { letter: String, color: u32 },
    /// A catalog symbol on `color`.
    Symbol { name: IconName, color: u32 },
    /// Custom image: the item's attachment `attachment` (a 128 px PNG). The view draws
    /// the decoded image, or the automatic icon while it is not available.
    Image { attachment: Uuid },
    /// An `icon.kind` this build cannot draw. Drawn as the letter avatar; the stored icon
    /// is kept as is.
    Unsupported {
        kind: String,
        letter: String,
        color: u32,
    },
}

impl IconSpec {
    /// Short description for debug selectors ("symbol Mail #3B6CF0").
    pub fn describe(&self) -> String {
        match self {
            Self::Letter { letter, color } => format!("letter {letter} #{color:06X}"),
            Self::Symbol { name, color } => format!("symbol {name:?} #{color:06X}"),
            Self::Image { .. } => "image".to_owned(),
            Self::Unsupported { kind, .. } => format!("unsupported {kind}"),
        }
    }

    /// User-facing name of what is shown ("Bank symbol", "Alarm clock symbol", "Letter").
    pub fn label(&self) -> String {
        match self {
            Self::Letter { .. } | Self::Unsupported { .. } => "Letter".to_owned(),
            Self::Symbol { name, .. } => format!("{} symbol", symbol_label(*name)),
            Self::Image { .. } => "Custom image".to_owned(),
        }
    }
}

/// `#RRGGBB` (either case) as `0xRRGGBB`.
pub fn parse_color(s: &str) -> Option<u32> {
    parse_hex6(s.strip_prefix('#')?)
}

/// `0xRRGGBB` as `#RRGGBB`, the stored form.
pub fn format_color(c: u32) -> String {
    format!("#{:06X}", c & 0xFF_FFFF)
}

fn parse_hex6(s: &str) -> Option<u32> {
    if s.len() != 6 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// The catalog icon stored as `name` (its `IconName` identifier), if this build has it.
pub fn symbol(name: &str) -> Option<IconName> {
    let (icons, ids, _) = &*CATALOG;
    ids.get(name).map(|&i| icons[i].icon)
}

/// Stored name of catalog icon `icon`.
pub fn symbol_name(icon: IconName) -> Option<&'static str> {
    catalog_entry(icon).map(|c| c.id.as_str())
}

/// Display name: the curated label, else the catalog name.
pub fn symbol_label(icon: IconName) -> String {
    SYMBOLS
        .iter()
        .find(|(_, i, _)| *i == icon)
        .map_or_else(|| catalog_label(icon), |(.., l)| (*l).to_owned())
}

/// The id-derived palette colour of `item`.
pub fn palette_color(item: &Item) -> u32 {
    PALETTE[listing::avatar_slot(item.id, PALETTE.len())]
}

/// What `item`'s tile shows: an explicit icon first, else the automatic letter.
pub fn resolve(item: &Item) -> IconSpec {
    let letter = || listing::avatar_letter(&item.title);
    let Some(icon) = &item.icon else {
        return automatic(item);
    };
    let color = color_override(Some(icon)).unwrap_or_else(|| palette_color(item));
    let as_letter = || IconSpec::Letter {
        letter: letter(),
        color,
    };
    match icon.kind.as_str() {
        KIND_SYMBOL => {
            symbol(&icon.value).map_or_else(as_letter, |name| IconSpec::Symbol { name, color })
        }
        // The removed brand pack's kind: no icon (owner decision 2026-11-16).
        KIND_LOGO => automatic(item),
        // "Automatic shape with a colour override": the letter in the chosen colour.
        KIND_LETTER => as_letter(),
        KIND_IMAGE => match image_attachment(icon) {
            Some(attachment) => IconSpec::Image { attachment },
            None => automatic(item),
        },
        other => IconSpec::Unsupported {
            kind: other.to_owned(),
            letter: letter(),
            color,
        },
    }
}

/// The attachment id an icon of kind `image` points at; `None` for other kinds and for a
/// value that is not a UUID.
pub fn image_attachment(icon: &ItemIcon) -> Option<Uuid> {
    if icon.kind != KIND_IMAGE {
        return None;
    }
    Uuid::parse_str(&icon.value).ok()
}

/// True when `r` holds `item`'s custom image icon. Such an attachment is an implementation
/// detail: it is never listed, counted, previewed or saved as a file by the app.
pub fn is_icon_attachment(item: &Item, r: &AttachmentRef) -> bool {
    item.icon
        .as_ref()
        .and_then(image_attachment)
        .is_some_and(|id| id == r.id)
}

/// The icon value for image attachment `id`: kind `image`, no colour.
pub fn image_icon(id: Uuid) -> ItemIcon {
    // `Uuid`'s `Display` is the lowercase hyphenated form the CLI also writes.
    ItemIcon::new(KIND_IMAGE, id.to_string())
}

/// What `item` shows with no icon set: the letter avatar in its palette colour.
pub fn automatic(item: &Item) -> IconSpec {
    IconSpec::Letter {
        letter: listing::avatar_letter(&item.title),
        color: palette_color(item),
    }
}

// --- Picker choices (edit mode). Each returns the new `Item.icon`. ---
//
// Shape and colour are independent (orchestrator decision 2026-10-31). Shape is
// Automatic or one symbol (or a custom image, chosen elsewhere); colour is an override
// of the item's palette colour, or none. Storage:
//   Automatic + default colour → no icon
//   Automatic + colour X       → kind `letter`, colour X
//   symbol S  + default colour → kind `symbol` S, no colour
//   symbol S  + colour X       → kind `symbol` S, colour X

/// The shape part of the picker: what the Automatic row and the symbol grid show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Automatic,
    Symbol(IconName),
    /// A custom image (`kind: image`).
    Image,
}

/// The shape `icon` stands for. Anything that is not a known symbol or an image (no
/// icon, `letter`, `logo`, an unknown kind or identifier) counts as Automatic.
pub fn shape(icon: Option<&ItemIcon>) -> Shape {
    match icon {
        Some(i) if i.kind == KIND_SYMBOL => {
            symbol(&i.value).map_or(Shape::Automatic, Shape::Symbol)
        }
        Some(i) if image_attachment(i).is_some() => Shape::Image,
        _ => Shape::Automatic,
    }
}

/// The colour override stored in `icon`, if any: one of the [`PALETTE`] colours, and
/// never on a legacy `logo` icon (no icon).
pub fn color_override(icon: Option<&ItemIcon>) -> Option<u32> {
    icon.filter(|i| i.kind != KIND_LOGO)
        .and_then(|i| i.color.as_deref())
        .and_then(parse_color)
        // Only the 8 swatches, all readable with a white glyph; any other stored
        // `#RRGGBB` (the CLI writes arbitrary ones) means the palette colour.
        .filter(|c| PALETTE.contains(c))
}

/// The colour the picker shows as selected: the override, else the item's palette colour.
pub fn effective_color(item: &Item) -> u32 {
    color_override(item.icon.as_ref()).unwrap_or_else(|| palette_color(item))
}

/// The icon for `shape` with colour override `color` (see the storage table above).
fn compose(shape: Shape, color: Option<u32>, current: Option<&ItemIcon>) -> Option<ItemIcon> {
    let with_color = |mut i: ItemIcon| {
        i.color = color.map(format_color);
        i
    };
    match shape {
        Shape::Automatic => color.map(|_| with_color(ItemIcon::new(KIND_LETTER, ""))),
        Shape::Symbol(icon) => symbol_name(icon).map(|n| with_color(ItemIcon::new(KIND_SYMBOL, n))),
        // An image carries no colour; it stays as it is.
        Shape::Image => current.cloned(),
    }
}

/// "Automatic": the automatic shape, keeping a colour override.
pub fn choose_automatic(current: Option<&ItemIcon>) -> Option<ItemIcon> {
    compose(Shape::Automatic, color_override(current), current)
}

/// A catalog symbol, keeping a colour override.
pub fn choose_symbol(current: Option<&ItemIcon>, icon: IconName) -> Option<ItemIcon> {
    compose(Shape::Symbol(icon), color_override(current), current)
}

/// A colour for the current shape. Picking `default` (the item's palette colour) clears
/// the override. On a custom image a colour means the automatic shape in that colour
/// (the image is given up, as the IC-3 brief has it).
pub fn choose_color(current: Option<&ItemIcon>, color: u32, default: u32) -> Option<ItemIcon> {
    let shape = match shape(current) {
        Shape::Image => Shape::Automatic,
        other => other,
    };
    let color = (color != default).then_some(color);
    compose(shape, color, current)
}

/// What "Automatic" means for `item` right now, for the picker's Automatic row: the
/// letter tinted with the colour override, or the palette colour without one. Updates
/// with every colour pick, like the header tile.
pub fn automatic_preview(item: &Item) -> IconSpec {
    IconSpec::Letter {
        letter: listing::avatar_letter(&item.title),
        color: effective_color(item),
    }
}

// --- Picker grid cursor (keyboard). ---

/// A cell of the picker: row 0 is "Automatic", then the symbol rows, one colour row, and
/// "Drop or choose image…" at the bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerCell {
    Automatic,
    Symbol(usize),
    Color(usize),
    Image,
    /// A catalog icon in the search results (not on the cursor grid).
    Icon(IconName),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Move {
    Up,
    Down,
    Left,
    Right,
}

const SYMBOL_ROWS: usize = SYMBOLS.len().div_ceil(GRID_COLS);
const COLOR_ROW: usize = 1 + SYMBOL_ROWS;
const IMAGE_ROW: usize = COLOR_ROW + 1;

/// Keyboard position in the picker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PickerCursor {
    row: usize,
    col: usize,
}

impl PickerCursor {
    pub fn at(cell: PickerCell) -> Self {
        match cell {
            PickerCell::Automatic | PickerCell::Icon(_) => Self { row: 0, col: 0 },
            PickerCell::Symbol(i) => Self {
                row: 1 + i / GRID_COLS,
                col: i % GRID_COLS,
            },
            PickerCell::Color(i) => Self {
                row: COLOR_ROW,
                col: i,
            },
            PickerCell::Image => Self {
                row: IMAGE_ROW,
                col: 0,
            },
        }
    }

    pub fn cell(self) -> PickerCell {
        match self.row {
            0 => PickerCell::Automatic,
            r if r == COLOR_ROW => PickerCell::Color(self.col),
            r if r == IMAGE_ROW => PickerCell::Image,
            r => PickerCell::Symbol((r - 1) * GRID_COLS + self.col),
        }
    }

    fn row_len(row: usize) -> usize {
        match row {
            0 | IMAGE_ROW => 1,
            r if r == COLOR_ROW => PALETTE.len(),
            r => (SYMBOLS.len() - (r - 1) * GRID_COLS).min(GRID_COLS),
        }
    }

    /// Arrows: left/right within a row (stopping at its ends), up/down between rows,
    /// keeping the column where the target row has one.
    pub fn step(self, m: Move) -> Self {
        let (row, col) = match m {
            Move::Left => (self.row, self.col.saturating_sub(1)),
            Move::Right => (self.row, self.col + 1),
            Move::Up => (self.row.saturating_sub(1), self.col),
            Move::Down => ((self.row + 1).min(IMAGE_ROW), self.col),
        };
        Self {
            row,
            col: col.min(Self::row_len(row) - 1),
        }
    }

    /// Arrows in a field's icon picker (05 "Field icons"): only "No icon" (the
    /// Automatic row) and the symbol rows exist there, so ↓ stops at the last symbol row.
    pub fn step_symbols(self, m: Move) -> Self {
        let next = self.step(m);
        if next.row > SYMBOL_ROWS { self } else { next }
    }

    /// Where a field's icon picker opens: on the field's symbol, else on "No icon".
    pub fn for_field_icon(name: Option<&str>) -> Self {
        name.and_then(|n| SYMBOLS.iter().position(|(s, ..)| *s == n))
            .map_or(Self::at(PickerCell::Automatic), |i| {
                Self::at(PickerCell::Symbol(i))
            })
    }

    /// Where the cursor starts when the picker opens: on the current shape (the colour
    /// row always shows its selection, so the cursor starts on the shape).
    pub fn for_icon(icon: Option<&ItemIcon>) -> Self {
        match shape(icon) {
            Shape::Image => Self::at(PickerCell::Image),
            Shape::Symbol(icon) => SYMBOLS
                .iter()
                .position(|(_, i, _)| *i == icon)
                .map_or(Self::at(PickerCell::Automatic), |i| {
                    Self::at(PickerCell::Symbol(i))
                }),
            Shape::Automatic => Self::at(PickerCell::Automatic),
        }
    }
}

#[cfg(test)]
#[path = "icon_tests.rs"]
mod tests;
