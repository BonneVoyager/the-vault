//! Item icons (specs/05-ui.md §2.3 item list and detail header): what an item's tile shows.
//!
//! Three layers, decided here without gpui; `screens::main::icon_view` draws the result.
//! 1. Automatic: the item's website field maps to a bundled Simple Icons brand logo
//!    (`assets/brand-icons.tsv`), else the letter avatar.
//! 2. Manual: `Item.icon` (01 §4) with kind `symbol` (a curated Lucide symbol plus a colour),
//!    `logo` (a pack slug), or `letter` (a colour-only choice tinting the letter avatar).
//! 3. Kind `image`: `value` is the id (lowercase hyphenated UUID) of an attachment of the
//!    same item holding a 128 px PNG ([`IconSpec::Image`]). That attachment is hidden from
//!    every attachment list ([`is_icon_attachment`]). A value that is not a UUID resolves to
//!    the automatic icon; a missing or undecodable blob is drawn as the automatic icon too.
//!    Any other kind this build does not know resolves to [`IconSpec::Unsupported`] and
//!    draws as the letter avatar. The stored value is never touched, so a newer app's
//!    choice survives.
//!
//! Website to logo (simplest interpretation, owner may refine): strip the scheme, path,
//! query, fragment, userinfo and port; lowercase; strip `www.`; drop a two-level public
//! suffix from [`TWO_LEVEL_SUFFIXES`] when the host ends in one, else drop the last label;
//! the label left at the end is the brand slug candidate (`mail.google.com` → `google`,
//! `bbc.co.uk` → `bbc`). IP addresses, single-label hosts and IPv6 literals have none. No
//! network lookups and no full public-suffix list.

use std::collections::HashMap;
use std::sync::LazyLock;

use gpui_kit_assets::IconName;
use vault_core::{AttachmentRef, ExposeSecret as _, FieldKind, Item, ItemIcon, Uuid};

use crate::listing;

/// Brand logos, Simple Icons 24×24 single-path SVGs: `slug\ttitle\thex\tpath` per line.
const BRAND_TSV: &str = include_str!("../assets/brand-icons.tsv");

/// Asset path prefix under which [`brand_svg`] serves pack logos (`brand/github.svg`).
pub const BRAND_ASSET_PREFIX: &str = "brand/";

/// `Item.icon.kind` values this build writes or reads.
pub const KIND_SYMBOL: &str = "symbol";
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

/// Public suffixes with two labels that the website mapping strips whole.
pub const TWO_LEVEL_SUFFIXES: [&str; 20] = [
    "co.uk", "com.au", "co.jp", "com.br", "co.nz", "co.za", "com.mx", "co.in", "org.uk", "ac.uk",
    "gov.uk", "net.au", "org.au", "co.kr", "com.tr", "com.ar", "com.sg", "com.hk", "co.il",
    "com.cn",
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

/// One brand of the bundled pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Brand {
    pub title: &'static str,
    pub hex: u32,
    /// SVG path data on a 24×24 viewBox.
    pub path: &'static str,
}

/// The bundled brand pack, parsed once on first use.
pub struct BrandPack {
    brands: HashMap<&'static str, Brand>,
}

static PACK: LazyLock<BrandPack> = LazyLock::new(|| BrandPack::parse(BRAND_TSV));

impl BrandPack {
    pub fn get() -> &'static BrandPack {
        &PACK
    }

    /// Parses `slug\ttitle\thex\tpath` lines. A malformed line is skipped, never fatal:
    /// a wrong field count, an empty slug, a hex that is not six hex digits, or path data
    /// with characters outside SVG path syntax (which also keeps it safe to splice into
    /// the generated SVG document).
    pub fn parse(tsv: &'static str) -> Self {
        let brands = tsv
            .lines()
            .filter_map(|line| {
                let mut parts = line.split('\t');
                let (slug, title, hex, path) =
                    (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
                if parts.next().is_some() || slug.is_empty() || path.is_empty() {
                    return None;
                }
                let path_ok = path
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || " .,-+".contains(c));
                if !path_ok {
                    return None;
                }
                let hex = parse_hex6(hex)?;
                Some((slug, Brand { title, hex, path }))
            })
            .collect();
        Self { brands }
    }

    pub fn brand(&self, slug: &str) -> Option<(&'static str, Brand)> {
        self.brands.get_key_value(slug).map(|(k, b)| (*k, *b))
    }

    #[cfg(test)]
    pub fn brand_count(&self) -> usize {
        self.brands.len()
    }
}

/// The SVG document for pack logo `slug`, served by the app asset source at
/// `brand/<slug>.svg`. gpui draws it as a one-colour mask, so it carries no fill.
pub fn brand_svg(slug: &str) -> Option<String> {
    let (_, brand) = BrandPack::get().brand(slug)?;
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\"><path d=\"{}\"/></svg>",
        brand.path
    ))
}

/// Asset path of pack logo `slug`.
pub fn brand_asset_path(slug: &str) -> String {
    format!("{BRAND_ASSET_PREFIX}{slug}.svg")
}

/// The brand-slug candidate for a website field value (see the module doc), or `None`.
pub fn registrable_label(raw: &str) -> Option<String> {
    let s = raw.trim();
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    let authority = s.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.starts_with('[') {
        return None; // IPv6 literal
    }
    let host = host_port.split(':').next().unwrap_or("");
    let host = host.trim_end_matches('.').to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    let mut labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let n = labels.len();
    let tail = format!("{}.{}", labels[n - 2], labels[n - 1]);
    labels.truncate(if TWO_LEVEL_SUFFIXES.contains(&tail.as_str()) {
        n - 2
    } else {
        n - 1
    });
    labels.last().map(|l| (*l).to_owned())
}

/// What an item's tile shows.
#[derive(Debug, Clone, PartialEq)]
pub enum IconSpec {
    /// Letter avatar: first letter of the title on `color`.
    Letter { letter: String, color: u32 },
    /// Pack logo `slug` in brand colour `hex`.
    Logo { slug: &'static str, hex: u32 },
    /// Curated symbol on `color`.
    Symbol { name: IconName, color: u32 },
    /// Custom image: the item's attachment `attachment` (a 128 px PNG). The view draws
    /// the decoded image, or the automatic icon while it is not available.
    Image { attachment: Uuid },
    /// An `icon.kind` this build cannot draw (e.g. `image` before layer 3). Drawn as the
    /// letter avatar; the stored icon is kept as is.
    Unsupported {
        kind: String,
        letter: String,
        color: u32,
    },
}

impl IconSpec {
    /// Short description for debug selectors and VoiceOver ("logo github").
    pub fn describe(&self) -> String {
        match self {
            Self::Letter { letter, color } => format!("letter {letter} #{color:06X}"),
            Self::Logo { slug, .. } => format!("logo {slug}"),
            Self::Symbol { name, color } => format!("symbol {name:?} #{color:06X}"),
            Self::Image { .. } => "image".to_owned(),
            Self::Unsupported { kind, .. } => format!("unsupported {kind}"),
        }
    }

    /// User-facing name of what is shown ("GitHub logo", "Bank symbol", "Letter").
    pub fn label(&self) -> String {
        match self {
            Self::Letter { .. } | Self::Unsupported { .. } => "Letter".to_owned(),
            Self::Logo { slug, .. } => BrandPack::get()
                .brand(slug)
                .map_or_else(|| "Logo".to_owned(), |(_, b)| format!("{} logo", b.title)),
            Self::Symbol { name, .. } => {
                symbol_label(*name).map_or_else(|| "Symbol".to_owned(), |l| format!("{l} symbol"))
            }
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

/// The symbol stored as `name`, if it is in the curated set.
pub fn symbol(name: &str) -> Option<IconName> {
    SYMBOLS
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|(_, i, _)| *i)
}

/// Stored name of symbol `icon`, if it is in the curated set.
pub fn symbol_name(icon: IconName) -> Option<&'static str> {
    SYMBOLS
        .iter()
        .find(|(_, i, _)| *i == icon)
        .map(|(n, ..)| *n)
}

fn symbol_label(icon: IconName) -> Option<&'static str> {
    SYMBOLS
        .iter()
        .find(|(_, i, _)| *i == icon)
        .map(|(.., l)| *l)
}

/// The id-derived palette colour of `item`.
pub fn palette_color(item: &Item) -> u32 {
    PALETTE[listing::avatar_slot(item.id, PALETTE.len())]
}

/// What `item`'s tile shows: an explicit icon first, else the automatic logo or letter.
pub fn resolve(item: &Item) -> IconSpec {
    let letter = || listing::avatar_letter(&item.title);
    let Some(icon) = &item.icon else {
        return automatic(item);
    };
    let color = icon
        .color
        .as_deref()
        .and_then(parse_color)
        .unwrap_or_else(|| palette_color(item));
    let as_letter = || IconSpec::Letter {
        letter: letter(),
        color,
    };
    match icon.kind.as_str() {
        KIND_SYMBOL => {
            symbol(&icon.value).map_or_else(as_letter, |name| IconSpec::Symbol { name, color })
        }
        KIND_LOGO => BrandPack::get()
            .brand(&icon.value)
            .map_or_else(as_letter, |(slug, b)| IconSpec::Logo { slug, hex: b.hex }),
        // "Automatic shape with a colour override" (orchestrator decision 2026-10-31):
        // the brand logo when one matches (logos keep the brand colour), else the letter
        // in the chosen colour.
        KIND_LETTER => match automatic(item) {
            logo @ IconSpec::Logo { .. } => logo,
            _ => as_letter(),
        },
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

/// What `item` shows with no icon set: the brand logo for its website, else the letter.
pub fn automatic(item: &Item) -> IconSpec {
    let logo = website(item)
        .and_then(|url| registrable_label(&url))
        .and_then(|label| BrandPack::get().brand(&label));
    match logo {
        Some((slug, b)) => IconSpec::Logo { slug, hex: b.hex },
        None => IconSpec::Letter {
            letter: listing::avatar_letter(&item.title),
            color: palette_color(item),
        },
    }
}

/// The website of `item`: its first URL field, else a non-sensitive field named "website".
fn website(item: &Item) -> Option<String> {
    item.fields
        .iter()
        .find(|f| f.kind == FieldKind::Url)
        .or_else(|| {
            item.fields
                .iter()
                // A section heading named "Website" is a heading: its value never counts.
                .find(|f| {
                    f.kind != FieldKind::Section
                        && f.name.eq_ignore_ascii_case("website")
                        && !f.kind.is_sensitive()
                })
        })
        .map(|f| f.value.expose_secret().to_owned())
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
/// icon, `letter`, `logo`, an unknown kind) counts as Automatic.
pub fn shape(icon: Option<&ItemIcon>) -> Shape {
    match icon {
        Some(i) if i.kind == KIND_SYMBOL => {
            symbol(&i.value).map_or(Shape::Automatic, Shape::Symbol)
        }
        Some(i) if image_attachment(i).is_some() => Shape::Image,
        _ => Shape::Automatic,
    }
}

/// The colour override stored in `icon`, if any (a valid `#RRGGBB`).
pub fn color_override(icon: Option<&ItemIcon>) -> Option<u32> {
    icon.and_then(|i| i.color.as_deref()).and_then(parse_color)
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

/// A symbol, keeping a colour override. A symbol outside the curated set changes nothing.
pub fn choose_symbol(current: Option<&ItemIcon>, icon: IconName) -> Option<ItemIcon> {
    if symbol_name(icon).is_none() {
        return current.cloned();
    }
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
/// automatic shape in the effective colour (the brand logo when one matches, else the
/// letter tinted with the colour override, or the palette colour without one). Updates
/// with every colour pick, like the header tile.
pub fn automatic_preview(item: &Item) -> IconSpec {
    match (automatic(item), color_override(item.icon.as_ref())) {
        (IconSpec::Letter { letter, .. }, Some(color)) => IconSpec::Letter { letter, color },
        (spec, _) => spec,
    }
}

/// Why the colour row is disabled for `item`: the Automatic shape resolves to a brand
/// logo, which keeps the brand colour. `None` when it is enabled.
pub fn color_disabled_reason(item: &Item) -> Option<&'static str> {
    let logo = matches!(automatic(item), IconSpec::Logo { .. });
    (shape(item.icon.as_ref()) == Shape::Automatic && logo).then_some("Logos use the brand colour")
}

// --- Tile colours. ---

/// Tile background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileBg {
    /// Filled with this colour.
    Fill(u32),
    /// The appearance's secondary surface (theme `secondary`).
    Surface,
}

/// Glyph colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    White,
    /// The tile's own colour (brand or chosen colour).
    Own(u32),
    /// The theme foreground.
    Foreground,
}

/// Above this relative luminance a colour is "near white": a white glyph on it falls under
/// 1.5:1 contrast. Such tiles use the neutral surface in both appearances.
pub const NEAR_WHITE: f32 = 0.65;
/// Below this a colour is "near black" (GitHub `#181717` is 0.009): in dark appearance it
/// disappears into the window, so the tile uses the neutral surface.
pub const NEAR_BLACK: f32 = 0.02;
/// Minimum contrast for drawing the glyph in its own colour on the neutral surface.
pub const GLYPH_CONTRAST: f32 = 3.0;

/// Background and glyph for a tile of colour `color` in the given appearance. `surface`
/// is the appearance's secondary surface. Usually a filled tile with a white glyph; a
/// near-white colour, or a near-black one in dark appearance, gets the neutral surface with
/// the glyph in its own colour, or in the foreground colour when that is unreadable too.
pub fn tile_look(color: u32, dark: bool, surface: u32) -> (TileBg, Glyph) {
    let l = luminance(color);
    let neutral = l > NEAR_WHITE || (dark && l < NEAR_BLACK);
    if !neutral {
        return (TileBg::Fill(color), Glyph::White);
    }
    let glyph = if contrast(color, surface) >= GLYPH_CONTRAST {
        Glyph::Own(color)
    } else {
        Glyph::Foreground
    };
    (TileBg::Surface, glyph)
}

/// WCAG relative luminance of `0xRRGGBB`.
pub fn luminance(c: u32) -> f32 {
    let lin = |v: u32| {
        let v = v as f32 / 255.;
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin((c >> 16) & 0xFF) + 0.7152 * lin((c >> 8) & 0xFF) + 0.0722 * lin(c & 0xFF)
}

/// WCAG contrast ratio of two colours.
pub fn contrast(a: u32, b: u32) -> f32 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
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
            PickerCell::Automatic => Self { row: 0, col: 0 },
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
