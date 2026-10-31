use std::sync::Arc;

use vault_core::{Field, SecretString, Uuid};

use super::*;

/// The vault theme's secondary surfaces (`bg_elevated`) and foregrounds.
const LIGHT_SURFACE: u32 = 0xF7F7F8;
const DARK_SURFACE: u32 = 0x2A2A2D;

fn item(title: &str, fields: &[(&str, FieldKind, &str)]) -> Item {
    let mut it = Item::new(title, Uuid::new_v4(), 1);
    it.fields = fields
        .iter()
        .map(|(n, k, v)| Field::new(*n, *k, SecretString::new((*v).into()), 1))
        .collect();
    it
}

fn with_icon(mut it: Item, kind: &str, value: &str, color: Option<&str>) -> Item {
    let mut icon = ItemIcon::new(kind, value);
    icon.color = color.map(str::to_owned);
    it.icon = Some(icon);
    it
}

fn hex_of(slug: &str) -> u32 {
    BrandPack::get().brand(slug).unwrap().1.hex
}

#[test]
fn registrable_label_cases() {
    let cases: &[(&str, Option<&str>)] = &[
        ("https://github.com/login", Some("github")),
        ("github.com", Some("github")),
        ("  HTTPS://WWW.GitHub.COM  ", Some("github")),
        ("https://mail.google.com/mail/u/0", Some("google")),
        ("https://www.bbc.co.uk/news", Some("bbc")),
        ("amazon.com.au", Some("amazon")),
        ("https://shop.rakuten.co.jp", Some("rakuten")),
        (
            "http://user:p@ss@accounts.example.com:8443/x?y#z",
            Some("example"),
        ),
        ("ftp://alice@files.example.org:21", Some("example")),
        ("example.com?q=1", Some("example")),
        ("https://bücher.de/", Some("bücher")),
        ("https://ПРИМЕР.рф", Some("пример")),
        ("example.com.", Some("example")),
        ("co.uk", None),
        ("localhost:8080", None),
        ("http://192.168.1.1/admin", None),
        ("http://[::1]:80/", None),
        ("", None),
        ("a..b.com", None),
    ];
    for (input, want) in cases {
        assert_eq!(
            registrable_label(input).as_deref(),
            *want,
            "input {input:?}"
        );
    }
}

#[test]
fn pack_loads_and_has_github() {
    let pack = BrandPack::get();
    assert!(pack.brand_count() > 3000, "{} brands", pack.brand_count());
    let (slug, gh) = pack.brand("github").unwrap();
    assert_eq!(slug, "github");
    assert_eq!(gh.title, "GitHub");
    assert!(!gh.path.is_empty());
    let svg = brand_svg("github").unwrap();
    assert!(svg.starts_with("<svg") && svg.contains(gh.path));
    assert_eq!(brand_svg("no-such-brand"), None);
}

#[test]
fn every_pack_svg_parses_with_gpuis_renderer() {
    struct NoAssets;
    impl gpui::AssetSource for NoAssets {
        fn load(&self, _: &str) -> gpui::Result<Option<std::borrow::Cow<'static, [u8]>>> {
            Ok(None)
        }
        fn list(&self, _: &str) -> gpui::Result<Vec<gpui::SharedString>> {
            Ok(Vec::new())
        }
    }
    let renderer = gpui::SvgRenderer::new(Arc::new(NoAssets));
    for slug in ["github", "google", "unity", "1001tracklists"] {
        let svg = brand_svg(slug).unwrap();
        assert!(renderer.parse_svg(svg.as_bytes()).is_ok(), "{slug}");
    }
}

#[test]
fn malformed_pack_lines_are_skipped() {
    let pack = BrandPack::parse(
        "ok\tOK\t00FF00\tM0 0h24v24H0z\n\
         short\tShort\t00FF00\n\
         badhex\tBad\t00FF0\tM0 0z\n\
         nothex\tBad\tGGGGGG\tM0 0z\n\
         inject\tBad\t000000\tM0 0\"/><script/>\n\
         \tNoSlug\t000000\tM0 0z\n\
         extra\tX\t000000\tM0 0z\tmore\n",
    );
    assert_eq!(pack.brand_count(), 1);
    assert!(pack.brand("ok").is_some());
}

#[test]
fn colour_parsing() {
    assert_eq!(parse_color("#3B6CF0"), Some(0x3B6CF0));
    assert_eq!(parse_color("#3b6cf0"), Some(0x3B6CF0));
    for bad in ["3B6CF0", "#3B6CF", "#3B6CF00", "#GGGGGG", "", "#", "red"] {
        assert_eq!(parse_color(bad), None, "{bad}");
    }
    assert_eq!(format_color(0x3B6CF0), "#3B6CF0");
    assert_eq!(format_color(0x00000A), "#00000A");
}

#[test]
fn resolve_automatic_logo_from_url_field() {
    let it = item(
        "Work account",
        &[("site", FieldKind::Url, "https://github.com/login")],
    );
    assert_eq!(
        resolve(&it),
        IconSpec::Logo {
            slug: "github",
            hex: hex_of("github")
        }
    );
}

#[test]
fn resolve_automatic_uses_a_website_field_and_skips_unknown_brands() {
    let it = item("Mail", &[("website", FieldKind::Text, "www.google.com")]);
    assert!(matches!(
        resolve(&it),
        IconSpec::Logo { slug: "google", .. }
    ));

    let it = item(
        "Bank",
        &[("url", FieldKind::Url, "https://my-tiny-bank.example")],
    );
    let IconSpec::Letter { letter, color } = resolve(&it) else {
        panic!("letter expected");
    };
    assert_eq!(letter, "B");
    assert_eq!(color, palette_color(&it));

    // A sensitive field named "website" is never read.
    let it = item("X", &[("website", FieldKind::Password, "github.com")]);
    assert!(matches!(resolve(&it), IconSpec::Letter { .. }));
    // The first URL field wins over a "website" text field.
    let it = item(
        "X",
        &[
            ("website", FieldKind::Text, "google.com"),
            ("url", FieldKind::Url, "github.com"),
        ],
    );
    assert!(matches!(
        resolve(&it),
        IconSpec::Logo { slug: "github", .. }
    ));
}

#[test]
fn resolve_explicit_kinds() {
    let base = || item("github", &[("url", FieldKind::Url, "github.com")]);
    // Symbol beats the automatic logo, with and without colour.
    assert_eq!(
        resolve(&with_icon(base(), "symbol", "Landmark", Some("#30A46C"))),
        IconSpec::Symbol {
            name: IconName::Landmark,
            color: 0x30A46C
        }
    );
    let it = with_icon(base(), "symbol", "Landmark", None);
    assert_eq!(
        resolve(&it),
        IconSpec::Symbol {
            name: IconName::Landmark,
            color: palette_color(&it)
        }
    );
    // Invalid colour falls back to the palette.
    let it = with_icon(base(), "symbol", "Mail", Some("blue"));
    assert_eq!(
        resolve(&it),
        IconSpec::Symbol {
            name: IconName::Mail,
            color: palette_color(&it)
        }
    );
    // Logo by slug.
    assert!(matches!(
        resolve(&with_icon(base(), "logo", "spotify", None)),
        IconSpec::Logo {
            slug: "spotify",
            ..
        }
    ));
    // A colour-only choice no longer turns a logo into a letter (2026-10-31).
    assert!(matches!(
        resolve(&with_icon(base(), "letter", "", Some("#E5484D"))),
        IconSpec::Logo { slug: "github", .. }
    ));
}

#[test]
fn unknown_kind_symbol_and_logo_fall_back_to_letter() {
    let base = || item("github", &[("url", FieldKind::Url, "github.com")]);
    let it = with_icon(base(), "hologram", "att-1", None);
    assert_eq!(
        resolve(&it),
        IconSpec::Unsupported {
            kind: "hologram".into(),
            letter: "G".into(),
            color: palette_color(&it)
        }
    );
    let it = with_icon(base(), "symbol", "NotASymbol", Some("#C2790A"));
    assert_eq!(
        resolve(&it),
        IconSpec::Letter {
            letter: "G".into(),
            color: 0xC2790A
        }
    );
    // Home is not an IconName variant name (it is House).
    assert!(matches!(
        resolve(&with_icon(base(), "symbol", "Home", None)),
        IconSpec::Letter { .. }
    ));
    let it = with_icon(base(), "logo", "no-such-brand", None);
    assert!(matches!(resolve(&it), IconSpec::Letter { .. }));
}

#[test]
fn every_symbol_is_served_by_the_app_assets() {
    use gpui::AssetSource as _;
    for (name, icon, _) in SYMBOLS {
        let path = icon.path();
        assert!(
            crate::assets::AppAssets.load(&path).unwrap().is_some(),
            "{name} ({path}) would render blank"
        );
    }
}

#[test]
fn symbol_names_match_icon_variants_and_are_unique() {
    for (name, icon, label) in SYMBOLS {
        assert_eq!(format!("{icon:?}"), name);
        assert_eq!(symbol(name), Some(icon));
        assert!(!label.is_empty());
    }
    let mut names: Vec<_> = SYMBOLS.iter().map(|(n, ..)| *n).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), SYMBOLS.len());
}

#[test]
fn contrast_rule_in_both_appearances() {
    let unity = hex_of("unity"); // FFFFFF
    let github = hex_of("github"); // 181717
    let netflix = hex_of("netflix"); // E50914
    assert_eq!(unity, 0xFFFFFF);

    // Saturated brand: filled tile, white glyph, both appearances.
    for dark in [false, true] {
        let surface = if dark { DARK_SURFACE } else { LIGHT_SURFACE };
        assert_eq!(
            tile_look(netflix, dark, surface),
            (TileBg::Fill(netflix), Glyph::White)
        );
    }
    // Near white: neutral tile. Light: the white glyph is unreadable on the light surface,
    // so foreground. Dark: the brand colour reads on the dark surface.
    assert_eq!(
        tile_look(unity, false, LIGHT_SURFACE),
        (TileBg::Surface, Glyph::Foreground)
    );
    assert_eq!(
        tile_look(unity, true, DARK_SURFACE),
        (TileBg::Surface, Glyph::Own(unity))
    );
    // Near black: filled in light, neutral with the foreground glyph in dark.
    assert_eq!(
        tile_look(github, false, LIGHT_SURFACE),
        (TileBg::Fill(github), Glyph::White)
    );
    assert_eq!(
        tile_look(github, true, DARK_SURFACE),
        (TileBg::Surface, Glyph::Foreground)
    );
    // Yellow (near white by luminance) reads on the dark surface in its own colour.
    assert_eq!(
        tile_look(0xFFDD00, true, DARK_SURFACE),
        (TileBg::Surface, Glyph::Own(0xFFDD00))
    );
    // Every palette colour is a filled tile in both appearances.
    for c in PALETTE {
        assert!(matches!(
            tile_look(c, false, LIGHT_SURFACE).0,
            TileBg::Fill(_)
        ));
        assert!(matches!(
            tile_look(c, true, DARK_SURFACE).0,
            TileBg::Fill(_)
        ));
    }
}

#[test]
fn picker_choices() {
    // The four storage mappings (default = the item's palette colour).
    let (default, x) = (PALETTE[0], PALETTE[4]);
    let triple = |i: &Option<ItemIcon>| {
        i.as_ref()
            .map(|i| (i.kind.clone(), i.value.clone(), i.color.clone()))
    };
    // Automatic + default → none; Automatic + X → letter X.
    assert_eq!(choose_color(None, default, default), None);
    let l = choose_color(None, x, default);
    assert_eq!(
        triple(&l),
        Some(("letter".into(), "".into(), Some(format_color(x))))
    );
    // Symbol + default → symbol, no colour; symbol + X → symbol, colour X.
    let s = choose_symbol(None, IconName::Bug);
    assert_eq!(triple(&s), Some(("symbol".into(), "Bug".into(), None)));
    let sx = choose_color(s.as_ref(), x, default);
    assert_eq!(
        triple(&sx),
        Some(("symbol".into(), "Bug".into(), Some(format_color(x))))
    );
    // Picking the default again clears the override, keeping the shape.
    assert_eq!(
        triple(&choose_color(sx.as_ref(), default, default)),
        triple(&s)
    );
    assert_eq!(choose_color(l.as_ref(), default, default), None);
    // Shape changes keep the colour: symbol keeps X, Automatic keeps X as a letter.
    assert_eq!(
        choose_symbol(l.as_ref(), IconName::Mail).unwrap().color,
        Some(format_color(x))
    );
    assert_eq!(triple(&choose_automatic(sx.as_ref())), triple(&l));
    assert_eq!(choose_automatic(s.as_ref()), None);
    assert_eq!(choose_automatic(None), None);
    // A symbol outside the set changes nothing.
    assert_eq!(choose_symbol(sx.as_ref(), IconName::Zap), sx);
    // Shapes.
    assert_eq!(shape(None), Shape::Automatic);
    assert_eq!(shape(l.as_ref()), Shape::Automatic);
    assert_eq!(shape(s.as_ref()), Shape::Symbol(IconName::Bug));
    let img = image_icon(vault_core::Uuid::new_v4());
    assert_eq!(shape(Some(&img)), Shape::Image);
    // A colour on an image: the automatic shape in that colour (the image is given up).
    assert_eq!(triple(&choose_color(Some(&img), x, default)), triple(&l));
    assert_eq!(choose_color(Some(&img), default, default), None);
}

#[test]
fn letter_kind_is_automatic_with_a_colour_override() {
    let logo_item = || item("github", &[("url", FieldKind::Url, "github.com")]);
    // A colour override on a logo-matching item still shows the logo.
    let it = with_icon(logo_item(), "letter", "", Some("#E5484D"));
    assert!(matches!(
        resolve(&it),
        IconSpec::Logo { slug: "github", .. }
    ));
    assert_eq!(
        color_disabled_reason(&it),
        Some("Logos use the brand colour")
    );
    assert_eq!(
        color_disabled_reason(&logo_item()),
        Some("Logos use the brand colour")
    );
    // Without a logo it is the tinted letter, and the colour row is enabled.
    let plain = with_icon(item("Bank", &[]), "letter", "", Some("#E5484D"));
    assert_eq!(
        resolve(&plain),
        IconSpec::Letter {
            letter: "B".into(),
            color: 0xE5484D
        }
    );
    assert_eq!(color_disabled_reason(&plain), None);
    assert_eq!(effective_color(&plain), 0xE5484D);
    // A symbol on a logo item can be coloured; no override means the palette colour.
    let sym = with_icon(logo_item(), "symbol", "Bug", None);
    assert_eq!(color_disabled_reason(&sym), None);
    assert_eq!(effective_color(&sym), palette_color(&sym));
}

#[test]
fn picker_cursor_moves_through_the_grid() {
    let start = PickerCursor::at(PickerCell::Automatic);
    assert_eq!(start.step(Move::Up), start);
    assert_eq!(start.step(Move::Right), start, "one cell in the top row");
    let first = start.step(Move::Down);
    assert_eq!(first.cell(), PickerCell::Symbol(0));
    assert_eq!(first.step(Move::Right).cell(), PickerCell::Symbol(1));
    assert_eq!(first.step(Move::Left).cell(), PickerCell::Symbol(0));
    assert_eq!(first.step(Move::Down).cell(), PickerCell::Symbol(GRID_COLS));
    // End of a row stops there.
    let row_end = PickerCursor::at(PickerCell::Symbol(GRID_COLS - 1));
    assert_eq!(row_end.step(Move::Right), row_end);
    // Last symbol row, then the colour row, which is the bottom.
    let last = PickerCursor::at(PickerCell::Symbol(SYMBOLS.len() - 1));
    let colour = last.step(Move::Down);
    assert!(matches!(colour.cell(), PickerCell::Color(_)));
    // "Drop or choose image…" is the bottom row, one cell wide.
    let image = colour.step(Move::Down);
    assert_eq!(image.cell(), PickerCell::Image);
    assert_eq!(image.step(Move::Down), image);
    assert_eq!(image.step(Move::Right), image);
    assert!(matches!(image.step(Move::Up).cell(), PickerCell::Color(0)));
    assert_eq!(
        PickerCursor::at(PickerCell::Image).cell(),
        PickerCell::Image
    );
    assert_eq!(colour.step(Move::Up).cell(), last.cell());
    // Up from any symbol in the first row lands on Automatic.
    assert_eq!(
        PickerCursor::at(PickerCell::Symbol(5))
            .step(Move::Up)
            .cell(),
        PickerCell::Automatic
    );
    // Round trip of every cell.
    for i in 0..SYMBOLS.len() {
        assert_eq!(
            PickerCursor::at(PickerCell::Symbol(i)).cell(),
            PickerCell::Symbol(i)
        );
    }
    for i in 0..PALETTE.len() {
        assert_eq!(
            PickerCursor::at(PickerCell::Color(i)).cell(),
            PickerCell::Color(i)
        );
    }
}

#[test]
fn picker_cursor_starts_on_the_current_choice() {
    assert_eq!(PickerCursor::for_icon(None).cell(), PickerCell::Automatic);
    let s = choose_symbol(None, IconName::Mail).unwrap();
    let mail = SYMBOLS.iter().position(|(n, ..)| *n == "Mail").unwrap();
    assert_eq!(
        PickerCursor::for_icon(Some(&s)).cell(),
        PickerCell::Symbol(mail)
    );
    // A colour-only choice is the Automatic shape: the cursor starts there.
    let l = choose_color(None, PALETTE[3], PALETTE[0]).unwrap();
    assert_eq!(
        PickerCursor::for_icon(Some(&l)).cell(),
        PickerCell::Automatic
    );
}

#[test]
fn image_kind_resolves_to_its_attachment() {
    let base = || item("github", &[("url", FieldKind::Url, "github.com")]);
    let id = vault_core::Uuid::new_v4();
    let it = with_icon(base(), "image", &id.to_string(), None);
    assert_eq!(resolve(&it), IconSpec::Image { attachment: id });
    assert_eq!(resolve(&it).label(), "Custom image");
    // Uppercase UUIDs parse too; a value that is not a UUID is the automatic icon.
    let upper = with_icon(base(), "image", &id.to_string().to_uppercase(), None);
    assert_eq!(resolve(&upper), IconSpec::Image { attachment: id });
    let bad = with_icon(base(), "image", "att-1", None);
    assert_eq!(resolve(&bad), automatic(&bad));
    assert!(matches!(
        resolve(&bad),
        IconSpec::Logo { slug: "github", .. }
    ));
    // The stored form is the lowercase hyphenated UUID, no colour.
    let icon = image_icon(id);
    assert_eq!(icon.kind, KIND_IMAGE);
    assert_eq!(icon.value, id.hyphenated().to_string());
    assert_eq!(icon.value, icon.value.to_lowercase());
    assert!(icon.color.is_none());
    assert_eq!(
        PickerCursor::for_icon(Some(&icon)).cell(),
        PickerCell::Image
    );
}

#[test]
fn only_the_icon_attachment_is_hidden() {
    let mut it = item("Bank", &[]);
    let icon_ref = vault_core::attachment::new_ref("icon.png", 10, 1).unwrap();
    let other = vault_core::attachment::new_ref("scan.pdf", 10, 1).unwrap();
    it.attachments = vec![icon_ref.clone(), other.clone()];
    assert!(!is_icon_attachment(&it, &icon_ref), "no icon set");
    it.icon = Some(image_icon(icon_ref.id));
    assert!(is_icon_attachment(&it, &icon_ref));
    assert!(!is_icon_attachment(&it, &other));
    // Same id under another kind, or a malformed value: nothing is hidden.
    it.icon = Some(vault_core::ItemIcon::new(
        "hologram",
        icon_ref.id.to_string(),
    ));
    assert!(!is_icon_attachment(&it, &icon_ref));
    it.icon = Some(vault_core::ItemIcon::new("image", "nope"));
    assert!(!is_icon_attachment(&it, &icon_ref));
}

#[test]
fn automatic_preview_uses_the_effective_colour() {
    let plain = item("Bank", &[]);
    assert_eq!(automatic_preview(&plain), automatic(&plain));
    let x = PALETTE[2];
    let tinted = with_icon(item("Bank", &[]), "symbol", "Bug", Some(&format_color(x)));
    assert_eq!(
        automatic_preview(&tinted),
        IconSpec::Letter {
            letter: "B".into(),
            color: x
        }
    );
    let logo = with_icon(
        item("gh", &[("url", FieldKind::Url, "github.com")]),
        "letter",
        "",
        Some(&format_color(x)),
    );
    assert!(matches!(
        automatic_preview(&logo),
        IconSpec::Logo { slug: "github", .. }
    ));
}
