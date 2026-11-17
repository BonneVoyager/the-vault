use vault_core::{Field, FieldKind, SecretString, Uuid};

use super::*;

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
fn resolve_explicit_kinds() {
    let base = || item("github", &[("url", FieldKind::Url, "github.com")]);
    // A symbol, with and without colour.
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
    // Any catalog icon, not only the 40 curated ones.
    assert_eq!(
        resolve(&with_icon(base(), "symbol", "AlarmClock", Some("#30A46C"))),
        IconSpec::Symbol {
            name: IconName::AlarmClock,
            color: 0x30A46C
        }
    );
    // A colour-only choice is the tinted letter, website or not.
    assert_eq!(
        resolve(&with_icon(base(), "letter", "", Some("#E5484D"))),
        IconSpec::Letter {
            letter: "G".into(),
            color: 0xE5484D
        }
    );
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
    // A catalog icon outside the 40 is stored by its identifier, keeping the colour.
    assert_eq!(
        triple(&choose_symbol(sx.as_ref(), IconName::Zap)),
        Some(("symbol".into(), "Zap".into(), Some(format_color(x))))
    );
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

/// The field icon picker has "No icon" and the symbol rows only: ↓ on the last symbol
/// row stays put (no colour or image row), ↑ from the first reaches "No icon".
#[test]
fn field_picker_cursor_stays_in_the_symbol_grid() {
    let last_row_start = (SYMBOLS.len() - 1) / GRID_COLS * GRID_COLS;
    for i in last_row_start..SYMBOLS.len() {
        let at = PickerCursor::at(PickerCell::Symbol(i));
        assert_eq!(at.step_symbols(Move::Down), at, "symbol {i} stays");
        assert!(matches!(at.step(Move::Down).cell(), PickerCell::Color(_)));
    }
    // A column the last row lacks: ↓ from the row above clamps into the last row.
    let above = PickerCursor::at(PickerCell::Symbol(last_row_start - 1));
    assert!(matches!(
        above.step_symbols(Move::Down).cell(),
        PickerCell::Symbol(i) if i >= last_row_start
    ));
    for i in 0..GRID_COLS {
        let up = PickerCursor::at(PickerCell::Symbol(i)).step_symbols(Move::Up);
        assert_eq!(up.cell(), PickerCell::Automatic, "symbol {i}");
        assert_eq!(up.step_symbols(Move::Up), up);
        assert_eq!(up.step_symbols(Move::Down).cell(), PickerCell::Symbol(0));
    }
    // Sideways moves are the item picker's.
    let mid = PickerCursor::at(PickerCell::Symbol(GRID_COLS + 3));
    for m in [Move::Left, Move::Right, Move::Up] {
        assert_eq!(mid.step_symbols(m), mid.step(m));
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
    assert!(matches!(resolve(&bad), IconSpec::Letter { .. }));
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
}

/// 05 "Item list" (2026-11-16): no brand logos. A website gives the letter avatar, and a
/// stored kind "logo" (older builds) is no icon.
#[test]
fn automatic_is_the_letter_and_logo_kind_is_no_icon() {
    let it = item(
        "Work account",
        &[("site", FieldKind::Url, "https://github.com/login")],
    );
    let letter = IconSpec::Letter {
        letter: "W".into(),
        color: palette_color(&it),
    };
    assert_eq!(resolve(&it), letter);
    assert_eq!(automatic(&it), letter);
    let logo = with_icon(it.clone(), "logo", "github", Some("#E5484D"));
    assert_eq!(
        resolve(&logo),
        letter,
        "kind logo = no icon, colour ignored"
    );
    assert_eq!(shape(logo.icon.as_ref()), Shape::Automatic);
    // Its colour is no override either: not in the picker, not written back.
    assert_eq!(color_override(logo.icon.as_ref()), None);
    assert_eq!(effective_color(&logo), palette_color(&logo));
    assert_eq!(automatic_preview(&logo), letter);
    assert_eq!(choose_automatic(logo.icon.as_ref()), None);
}

/// Stored colours outside the 8 swatches (the CLI writes any `#RRGGBB`) draw in the
/// item's palette colour, so a white glyph always reads (05 "Icon search").
#[test]
fn only_palette_colours_are_drawn() {
    let base = || item("Bank", &[]);
    let white = with_icon(base(), "symbol", "Mail", Some("#FFFFFF"));
    assert_eq!(
        resolve(&white),
        IconSpec::Symbol {
            name: IconName::Mail,
            color: palette_color(&white)
        }
    );
    assert_eq!(effective_color(&white), palette_color(&white));
    let tinted = with_icon(base(), "letter", "", Some("#ffffff"));
    assert_eq!(
        resolve(&tinted),
        IconSpec::Letter {
            letter: "B".into(),
            color: palette_color(&tinted)
        }
    );
    // A palette colour is kept (either case).
    let kept = with_icon(base(), "symbol", "Mail", Some("#8e4ec6"));
    assert_eq!(
        resolve(&kept),
        IconSpec::Symbol {
            name: IconName::Mail,
            color: 0x8E4EC6
        }
    );
    assert_eq!(effective_color(&kept), 0x8E4EC6);
}

fn words(hits: &[PickerCell]) -> Vec<String> {
    hits.iter()
        .map(|h| match h {
            PickerCell::Symbol(i) => format!("*{}", SYMBOLS[*i].0),
            PickerCell::Icon(icon) => format!("{icon:?}"),
            other => format!("{other:?}"),
        })
        .collect()
}

/// 05 "Icon search": curated symbols first, then name-prefix matches, then the others,
/// alphabetical (by kebab name) within each; hyphens count as spaces; capped at 120.
#[test]
fn icon_search_ranking_and_cap() {
    assert!(search("").is_empty(), "empty query: the plain symbol grid");
    assert!(search("   ").is_empty());
    let clock = words(&search("Clock"));
    assert_eq!(&clock[..4], ["Clock", "Clock1", "Clock10", "Clock11"]);
    let first_other = clock.iter().position(|w| w == "AlarmClock").unwrap();
    assert_eq!(first_other, 21, "21 names start with clock");
    assert_eq!(
        &clock[first_other..first_other + 3],
        ["AlarmClock", "AlarmClockCheck", "AlarmClockMinus"]
    );
    assert_eq!(clock.last().unwrap(), "RotateCwFadingClock");
    // Curated symbols first (by label, identifier or name), then the catalog without them.
    let mail = words(&search("mail"));
    assert_eq!(mail[0], "*Mail");
    assert_eq!(&mail[1..3], ["MailBadge", "MailCheck"]);
    assert_eq!(mail.last().unwrap(), "Voicemail");
    assert_eq!(
        mail.iter().filter(|w| w.ends_with("Mail")).count(),
        1,
        "no duplicate"
    );
    let term = words(&search("terminal"));
    assert_eq!(term[0], "*SquareTerminal", "curated by label");
    // Hyphens are spaces; case does not matter.
    assert_eq!(search("alarm-clock"), search("ALARM CLOCK"));
    assert_eq!(words(&search("alarm-clock"))[0], "AlarmClock");
    assert_eq!(search("a").len(), SEARCH_CAP);
    assert_eq!(SEARCH_CAP, 120);
    assert!(search("zzzqqqxx").is_empty());
}

#[test]
fn picker_search_steps_and_picks_once_per_query() {
    let mut s = PickerSearch::default();
    SEARCH_CALLS.with(|c| c.set(0));
    assert!(s.set_query("clock".into()));
    assert!(!s.set_query("clock".into()), "unchanged query: no search");
    assert_eq!(SEARCH_CALLS.with(|c| c.get()), 1);
    assert!(s.active());
    assert_eq!(
        s.chosen(),
        Some(PickerCell::Icon(IconName::Clock)),
        "Enter: first"
    );
    s.step(Move::Down);
    assert_eq!(s.hit(), Some(0));
    s.step(Move::Down);
    s.step(Move::Right);
    assert_eq!(s.hit(), Some(GRID_COLS + 1));
    s.step(Move::Up);
    s.step(Move::Up);
    assert_eq!(s.hit(), None, "back in the field");
    assert_eq!(cell_icon(PickerCell::Symbol(0)), Some(SYMBOLS[0].1));
    assert_eq!(symbol_label(IconName::AlarmClock), "Alarm clock");
    assert_eq!(symbol_label(IconName::Landmark), "Bank");
}

/// Bug-hunt 2026-11-17 note 3: `vault edit --icon symbol:key-round` stores Lucide's kebab
/// name; the PascalCase identifier and the kebab name (any case) resolve to one icon.
#[test]
fn stored_symbol_accepts_identifier_and_kebab_name() {
    for name in ["KeyRound", "key-round", "Key-Round", "KEY-ROUND"] {
        assert_eq!(symbol(name), Some(IconName::KeyRound), "{name}");
        let it = with_icon(item("github", &[]), "symbol", name, None);
        assert!(
            matches!(
                resolve(&it),
                IconSpec::Symbol {
                    name: IconName::KeyRound,
                    ..
                }
            ),
            "{name}"
        );
        assert_eq!(shape(it.icon.as_ref()), Shape::Symbol(IconName::KeyRound));
        assert_eq!(
            PickerCursor::for_icon(it.icon.as_ref()).cell(),
            PickerCursor::for_icon(choose_symbol(None, IconName::KeyRound).as_ref()).cell()
        );
    }
    // A catalog icon outside the curated set, digits included.
    assert_eq!(symbol("gamepad-2"), Some(IconName::Gamepad2));
    assert_eq!(symbol("Gamepad2"), Some(IconName::Gamepad2));
    // Only the identifier is exact-case; a lowercase identifier is not a kebab name.
    assert_eq!(symbol("keyround"), None);
    assert_eq!(symbol("key round"), None);
    // Mixed case is lowercased in a SYMBOL_NAME_MAX-byte stack buffer: a longer name
    // fails to resolve instead of allocating; a long lowercase name is looked up as is.
    let long_upper = format!("Key-Round{}", "x".repeat(SYMBOL_NAME_MAX));
    assert_eq!(symbol(&long_upper), None);
    assert_eq!(symbol(&long_upper.to_ascii_lowercase()), None);
    assert_eq!(symbol("KEY-ROUND-É"), None);
    // The picker keeps writing the identifier.
    let s = choose_symbol(None, IconName::KeyRound).unwrap();
    assert_eq!(s.value, "KeyRound");
    assert_eq!(symbol_name(IconName::KeyRound), Some("KeyRound"));
}

#[test]
fn unknown_stored_symbol_still_falls_back_to_letter() {
    for name in ["no-such-icon", "NoSuchIcon", "", "-", "key-round-"] {
        let it = with_icon(item("github", &[]), "symbol", name, None);
        assert!(
            matches!(resolve(&it), IconSpec::Letter { .. }),
            "{name}: {:?}",
            resolve(&it)
        );
        assert_eq!(shape(it.icon.as_ref()), Shape::Automatic, "{name}");
    }
}

/// Field icons (`Field.icon`) go through the same lookup: read-mode rows and the drag
/// preview call `symbol`, and the field picker opens on the matching curated cell.
#[test]
fn field_icon_accepts_identifier_and_kebab_name() {
    let key = SYMBOLS
        .iter()
        .position(|(_, i, _)| *i == IconName::KeyRound)
        .unwrap();
    for name in ["KeyRound", "key-round", "Key-Round"] {
        let mut f = Field::new("PIN", FieldKind::Text, SecretString::new("1".into()), 1);
        f.icon = Some(name.to_owned());
        assert_eq!(
            f.icon_name().and_then(symbol),
            Some(IconName::KeyRound),
            "{name}"
        );
        assert_eq!(
            PickerCursor::for_field_icon(f.icon_name()).cell(),
            PickerCell::Symbol(key),
            "{name}"
        );
    }
    assert_eq!(symbol("no-such-icon"), None);
    assert_eq!(
        PickerCursor::for_field_icon(Some("no-such-icon")).cell(),
        PickerCell::Automatic
    );
}
