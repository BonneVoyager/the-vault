//! Headless tests driving the real main screen: the editor's inputs, save, and the
//! detail column that renders the result.

use std::sync::Arc;

use gpui::{TestAppContext, VisualTestContext};
use gpui_component::Root;
use vault_core::{KdfParams, SecretString, Totp, Uuid};
use vault_sync::{NoopHooks, SyncedVault};

use super::super::MainScreen;
use super::*;
use crate::actions;

const PW: &str = "pw";
const URI: &str = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

/// The main screen over an empty unlocked vault.
pub(super) fn open(
    dir: &std::path::Path,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, Entity<MainScreen>, VisualTestContext) {
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    let mut v = SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new(PW.into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    v.save().unwrap();
    let path = v.path().to_owned();
    drop(v);
    cx.update(|cx| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        actions::register(&state, cx);
    });
    state.update(cx, |s, cx| s.open_vault(path, cx));
    cx.run_until_parked();
    state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
    cx.run_until_parked();
    let mut main = None;
    let window = cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|cx| MainScreen::new(state.clone(), None, window, cx));
        main = Some(view.clone());
        Root::new(view, window, cx)
    });
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    let main = main.unwrap();
    vcx.update(|window, cx| main.update(cx, |m, cx| m.appear(window, cx)));
    vcx.run_until_parked();
    (state, main, vcx)
}

/// The single-line value input of row `key`.
pub(super) fn value_input(
    main: &Entity<MainScreen>,
    key: u64,
    vcx: &mut VisualTestContext,
) -> Entity<InputState> {
    main.read_with(vcx, |m, cx| {
        let editor = m.editor.read(cx);
        match &editor
            .rows
            .iter()
            .find(|r| r.key == key)
            .expect("row")
            .value
        {
            ValueInput::Line(i) => i.clone(),
            ValueInput::Area(_) | ValueInput::None => panic!("not a line input"),
        }
    })
}

/// Types `text` into `input` like the user would.
fn type_into(input: &Entity<InputState>, text: &str, vcx: &mut VisualTestContext) {
    vcx.update(|window, cx| ui::focus_input(input, window, cx));
    vcx.simulate_input(text);
    vcx.run_until_parked();
}

/// True when the detail column shows the current (or just-expired) code of `uri`.
pub(super) fn shows_code(uri: &str, vcx: &mut VisualTestContext) -> bool {
    let totp = Totp::parse_uri(uri).unwrap();
    let now = crate::text::now_millis() / 1000;
    [now, now.saturating_sub(30)].into_iter().any(|t| {
        let key = format!("totp-code {}", crate::text::group_code(&totp.code(t)));
        vcx.debug_bounds(Box::leak(key.into_boxed_str())).is_some()
    })
}

/// An unknown field kind (from a newer app version) edits in a masked input and is
/// never offered in "Add field".
#[gpui::test]
fn unknown_field_kind_uses_a_masked_input(cx: &mut TestAppContext) {
    assert!(
        !FieldKind::ALL.contains(&FieldKind::Other),
        "not in Add field"
    );
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, "Example".into(), cx)
    });
    vcx.run_until_parked();
    let (other, text) = state.update(&mut vcx, |s, cx| {
        let mut keys = (0, 0);
        s.edit(cx, |b| {
            keys = (b.add_field(FieldKind::Other), b.add_field(FieldKind::Text))
        });
        keys
    });
    vcx.run_until_parked();
    let other = value_input(&main, other, &mut vcx);
    let text = value_input(&main, text, &mut vcx);
    vcx.update(|_, cx| {
        assert!(ui::input_is_masked(&other, cx), "Other is masked");
        assert!(!ui::input_is_masked(&text, cx), "Text is not");
    });
}

#[gpui::test]
fn typed_totp_uri_shows_a_code_after_save(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, "Example".into(), cx)
    });
    vcx.run_until_parked();
    // "Add field" ▸ one-time code.
    let key = state.update(&mut vcx, |s, cx| {
        let mut key = 0;
        s.edit(cx, |b| key = b.add_field(FieldKind::Totp));
        key
    });
    vcx.run_until_parked();
    let input = value_input(&main, key, &mut vcx);
    type_into(&input, URI, &mut vcx);
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(
            !s.is_editing(),
            "{:?}",
            s.edit_buffer().and_then(|b| b.error.clone())
        );
        let item = s.selected_item().expect("new item selected");
        let f = item
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        assert_eq!(f.value.expose_secret(), URI);
    });
    vcx.run_until_parked();
    assert!(
        vcx.debug_bounds("totp-invalid").is_none(),
        "shows the invalid line"
    );
    assert!(shows_code(URI, &mut vcx), "a 6-digit grouped code is shown");
}

#[gpui::test]
fn pasted_uri_in_an_existing_item_is_trimmed_and_works(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, "Example".into(), cx)
    });
    vcx.run_until_parked();
    vcx.simulate_keystrokes("cmd-s");
    vcx.simulate_keystrokes("cmd-e");
    vcx.run_until_parked();
    let key = state.update(&mut vcx, |s, cx| {
        let mut key = 0;
        s.edit(cx, |b| key = b.add_field(FieldKind::Totp));
        key
    });
    vcx.run_until_parked();
    let input = value_input(&main, key, &mut vcx);
    vcx.update(|window, cx| {
        ui::focus_input(&input, window, cx);
        cx.write_to_clipboard(gpui::ClipboardItem::new_string(format!(" {URI}\n")));
    });
    vcx.simulate_keystrokes("cmd-v");
    vcx.run_until_parked();
    assert!(
        vcx.debug_bounds("totp-hint Valid one-time code").is_some(),
        "inline status while editing"
    );
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        let item = s.selected_item().unwrap();
        let f = item
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        assert_eq!(f.value.expose_secret(), URI, "stored trimmed");
    });
    assert!(shows_code(URI, &mut vcx));
}

#[gpui::test]
fn invalid_value_is_flagged_at_edit_time_and_bare_secret_saves_as_uri(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, "Bank".into(), cx)
    });
    vcx.run_until_parked();
    let key = state.update(&mut vcx, |s, cx| {
        let mut key = 0;
        s.edit(cx, |b| key = b.add_field(FieldKind::Totp));
        key
    });
    vcx.run_until_parked();
    assert!(
        vcx.debug_bounds("totp-hint Valid one-time code").is_none(),
        "empty: no hint"
    );
    let input = value_input(&main, key, &mut vcx);
    type_into(&input, "otpauth://totp/x?secret=1", &mut vcx);
    assert!(
        vcx.debug_bounds("totp-hint Not a valid otpauth URI or base32 secret")
            .is_some()
    );
    vcx.update(|window, cx| ui::clear_input(&input, window, cx));
    type_into(&input, "JBSWY3DPEHPK3PXP", &mut vcx);
    assert!(
        vcx.debug_bounds("totp-hint Valid one-time code secret (saved as an otpauth:// URI)")
            .is_some()
    );
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    let stored = state.read_with(&vcx, |s, _| {
        let item = s.selected_item().unwrap();
        let f = item
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        f.value.expose_secret().to_owned()
    });
    assert!(
        stored.starts_with("otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP"),
        "{}",
        stored.len()
    );
    assert!(shows_code(&stored, &mut vcx));
}

#[gpui::test]
fn tag_input_commits_on_enter_and_comma_and_backspace_removes(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, "Example".into(), cx)
    });
    vcx.run_until_parked();
    let tags = main.read_with(&vcx, |m, cx| m.editor.read(cx).tags.clone());
    let buffer_tags = |vcx: &mut VisualTestContext| {
        state.read_with(vcx, |s, _| s.edit_buffer().unwrap().item.tags.clone())
    };

    type_into(&tags, "work", &mut vcx);
    vcx.simulate_keystrokes("enter");
    vcx.run_until_parked();
    // The Login template already added its tag.
    assert_eq!(buffer_tags(&mut vcx), ["login", "work"]);
    assert!(ui::input_is_empty(&tags, &vcx.app.borrow()));

    type_into(&tags, "#home,Work,", &mut vcx);
    assert_eq!(
        buffer_tags(&mut vcx),
        ["login", "work", "home"],
        "comma commits, dupes dropped"
    );
    assert!(ui::input_is_empty(&tags, &vcx.app.borrow()));

    // Backspace deletes typed text first; in an empty input it removes the last chip.
    type_into(&tags, "x", &mut vcx);
    vcx.simulate_keystrokes("backspace");
    vcx.run_until_parked();
    assert_eq!(buffer_tags(&mut vcx), ["login", "work", "home"]);
    vcx.simulate_keystrokes("backspace");
    vcx.run_until_parked();
    assert_eq!(buffer_tags(&mut vcx), ["login", "work"]);

    // An uncommitted draft is saved too.
    type_into(&tags, "  #infra ", &mut vcx);
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(!s.is_editing());
        assert_eq!(s.selected_item().unwrap().tags, ["login", "work", "infra"]);
        let names: Vec<_> = s.counts.tags.iter().map(|t| t.0.as_str()).collect();
        assert_eq!(names, ["infra", "login", "work"]);
    });

    // Next edit starts with an empty tag input; the chip's × removes a tag.
    vcx.simulate_keystrokes("cmd-e");
    vcx.run_until_parked();
    assert!(ui::input_is_empty(&tags, &vcx.app.borrow()));
    state.update(&mut vcx, |s, cx| s.edit(cx, |b| b.remove_tag(0)));
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.selected_item().unwrap().tags, ["work", "infra"])
    });
}

/// The tags row has a fixed height: adding the first tag (or enough to overflow the
/// row) does not move the field rows below it.
#[gpui::test]
fn first_tag_does_not_shift_the_field_rows(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        let device = s.device_id();
        let id = s
            .vault
            .as_mut()
            .unwrap()
            .edit(|v| {
                let mut it = vault_core::Item::new("Plain", device, 10);
                it.fields = vec![vault_core::Field::new(
                    "username",
                    FieldKind::Text,
                    SecretString::new("chris".into()),
                    10,
                )];
                v.insert(it, 10)
            })
            .unwrap();
        s.vault_changed();
        s.select(id, cx);
        s.begin_edit(cx);
    });
    vcx.run_until_parked();
    assert!(state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().item.tags.is_empty()));
    let measure = |vcx: &mut VisualTestContext| {
        let tags = vcx.debug_bounds("edit-tags").expect("tags row rendered");
        let row = vcx.debug_bounds("edit-row 0").expect("field row");
        (tags.size.height, row.origin.y)
    };
    let before = measure(&mut vcx);

    state.update(&mut vcx, |s, cx| {
        s.edit(cx, |b| {
            b.add_tag("work");
        })
    });
    vcx.run_until_parked();
    assert_eq!(measure(&mut vcx), before, "first tag shifted the layout");

    state.update(&mut vcx, |s, cx| {
        s.edit(cx, |b| {
            for i in 0..12 {
                b.add_tag(&format!("a-rather-long-tag-{i}"));
            }
        })
    });
    vcx.run_until_parked();
    assert_eq!(measure(&mut vcx), before, "many tags grew the row");

    // The input sits outside the scrolling chip strip, so it stays inside the row.
    let inside = |outer: gpui::Bounds<gpui::Pixels>, inner: gpui::Bounds<gpui::Pixels>| {
        inner.left() >= outer.left() - px(0.5) && inner.right() <= outer.right() + px(0.5)
    };
    let row = vcx.debug_bounds("edit-tags").unwrap();
    let input = vcx.debug_bounds("edit-tag-input").expect("tag input");
    assert!(inside(row, input), "input {input:?} outside row {row:?}");

    // Adding one more scrolls the strip so the newest chip (and its ×) is visible.
    state.update(&mut vcx, |s, cx| {
        s.edit(cx, |b| {
            b.add_tag("newest");
        })
    });
    vcx.run_until_parked();
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
    let strip = vcx.debug_bounds("edit-tag-chips").unwrap();
    let last = vcx.debug_bounds("edit-tag-chip 12").expect("13th chip");
    assert!(
        inside(strip, last),
        "last chip {last:?} not visible in {strip:?}"
    );
    let input = vcx.debug_bounds("edit-tag-input").unwrap();
    assert!(inside(row, input), "input pushed out after an add");
}

/// Trash buttons appear on history entries in edit mode only; clicking one marks
/// just that entry, reveals nothing, and "Clear history" marks the rest.
#[gpui::test]
fn history_trash_buttons_only_in_edit_mode(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let stamps = state.update(&mut vcx, |s, cx| {
        let device = s.device_id();
        let id = s
            .vault
            .as_mut()
            .unwrap()
            .edit(|v| {
                let mut it = vault_core::Item::new("GitHub", device, 10);
                it.fields = vec![vault_core::Field::new(
                    "password",
                    FieldKind::Password,
                    SecretString::new("a".into()),
                    10,
                )];
                let id = v.insert(it, 10);
                v.set_field_named(id, "password", SecretString::new("b".into()), 20)?;
                v.set_field_named(id, "password", SecretString::new("c".into()), 30)?;
                Ok::<_, vault_core::VaultError>(id)
            })
            .unwrap()
            .unwrap();
        s.vault_changed();
        s.select(id, cx);
        s.toggle_history(cx);
        let item = s.selected_item().unwrap();
        item.history
            .iter()
            .map(|h| h.replaced_at)
            .collect::<Vec<_>>()
    });
    assert_eq!(stamps.len(), 2);
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("history-remove 0").is_none(), "read mode");
    assert!(vcx.debug_bounds("history-clear").is_none(), "read mode");

    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("history-remove 1").is_some());
    let trash = vcx.debug_bounds("history-remove 0").expect("trash button");
    vcx.simulate_click(trash.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        assert_eq!(b.removed_history, vec![stamps[0]]);
        assert!(s.revealed.is_empty(), "removing reveals nothing");
        assert_eq!(s.selected_item().unwrap().history.len(), 2, "not saved yet");
    });
    assert!(vcx.debug_bounds("history-remove 1").is_none(), "one left");

    let clear = vcx.debug_bounds("history-clear").expect("clear button");
    vcx.simulate_click(clear.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.edit_buffer().unwrap().history().count(), 0);
    });
    assert!(vcx.debug_bounds("history-remove 0").is_none());
    assert!(vcx.debug_bounds("history-clear").is_none());
    // The disclosure stays, reading "(0) · 2 removed on save".
    assert!(vcx.debug_bounds("history-toggle").is_some(), "toggle kept");
    assert!(
        vcx.debug_bounds("history-removed 2").is_some(),
        "removed note"
    );
}

#[gpui::test]
fn icon_picker_opens_from_the_tile_and_works_by_keyboard(cx: &mut TestAppContext) {
    use crate::icon::{PALETTE, SYMBOLS};
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let id = state.update(&mut vcx, |s, cx| {
        let device = s.device_id();
        let id = s
            .vault
            .as_mut()
            .unwrap()
            .edit(|v| {
                let mut it = vault_core::Item::new("Work", device, 10);
                it.fields = vec![vault_core::Field::new(
                    "url",
                    FieldKind::Url,
                    SecretString::new("https://github.com/login".into()),
                    10,
                )];
                v.insert(it, 10)
            })
            .unwrap();
        s.vault_changed();
        s.select(id, cx);
        id
    });
    vcx.run_until_parked();
    // Automatic: the letter avatar, also with a website (no brand logos since 2026-11-16).
    let auto = state.read_with(&vcx, |s, _| {
        crate::icon::automatic(s.selected_item().unwrap()).describe()
    });
    assert!(auto.starts_with("letter W "), "{auto}");
    assert!(
        vcx.debug_bounds(leak(format!("icon-tile {auto} fill white")))
            .is_some(),
        "automatic letter"
    );

    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let tile = vcx.debug_bounds("edit-icon").expect("edit-mode tile");
    vcx.simulate_click(tile.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("icon-picker").is_some(), "picker open");
    assert!(vcx.debug_bounds("icon-picker-automatic").is_some());
    assert!(vcx.debug_bounds("icon-symbol 39").is_some(), "40 symbols");
    assert!(vcx.debug_bounds("icon-color 7").is_some(), "8 swatches");

    // Arrows move from "Automatic" to the second symbol; Enter picks it.
    vcx.simulate_keystrokes("down right enter");
    vcx.run_until_parked();
    let icon = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().item.icon.clone());
    assert_eq!(icon.as_ref().map(|i| i.value.as_str()), Some(SYMBOLS[1].0));

    // A swatch click recolours it (one that is not the item's default); the header
    // tile follows.
    let default = state.read_with(&vcx, |s, _| {
        crate::icon::palette_color(&s.edit_buffer().unwrap().item)
    });
    let ix = PALETTE.iter().position(|c| *c != default).unwrap();
    let swatch_sel: &'static str = Box::leak(format!("icon-color {ix}").into_boxed_str());
    let swatch = vcx.debug_bounds(swatch_sel).unwrap();
    vcx.simulate_click(swatch.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    let want: &'static str = Box::leak(
        format!(
            "icon-tile symbol {:?} #{:06X} fill white",
            SYMBOLS[1].1, PALETTE[ix]
        )
        .into_boxed_str(),
    );
    assert!(vcx.debug_bounds(want).is_some(), "{want}");

    // Esc closes the picker but not the edit.
    vcx.simulate_keystrokes("escape");
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("icon-picker").is_none(), "picker closed");
    state.read_with(&vcx, |s, _| {
        assert!(s.is_editing(), "Esc in the picker keeps editing");
        assert_eq!(s.edit_buffer().unwrap().icon_picker, None);
    });

    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    let saved = state.read_with(&vcx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().icon.clone()
    });
    assert_eq!(
        saved.unwrap().color,
        Some(crate::icon::format_color(PALETTE[ix]))
    );
    assert!(
        vcx.debug_bounds(want).is_some(),
        "read-mode header shows the symbol"
    );
}

/// Inserts `item` into the open vault and selects it; returns its id.
pub(super) fn insert_and_select(
    state: &Entity<AppState>,
    item: vault_core::Item,
    vcx: &mut VisualTestContext,
) -> Uuid {
    let id = state.update(vcx, |s, cx| {
        let id = s
            .vault
            .as_mut()
            .unwrap()
            .edit(|v| v.insert(item, 10))
            .unwrap();
        s.vault_changed();
        s.select(id, cx);
        id
    });
    vcx.run_until_parked();
    id
}

fn title_focused(main: &Entity<MainScreen>, vcx: &mut VisualTestContext) -> bool {
    vcx.update(|window, cx| {
        let title = main.read(cx).editor.read(cx).title.clone();
        gpui::Focusable::focus_handle(&title, cx).is_focused(window)
    })
}

#[gpui::test]
fn esc_in_the_icon_picker_returns_focus_to_the_title(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    insert_and_select(&state, vault_core::Item::new("Work", device, 10), &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    // Start somewhere else than the title (the popover would otherwise just restore it).
    vcx.update(|window, cx| {
        let tags = main.read(cx).editor.read(cx).tags.clone();
        crate::ui::focus_input(&tags, window, cx);
    });
    vcx.run_until_parked();
    assert!(!title_focused(&main, &mut vcx));
    let tile = vcx.debug_bounds("edit-icon").unwrap();
    vcx.simulate_click(tile.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("icon-picker").is_some());
    assert!(!title_focused(&main, &mut vcx), "the picker has the focus");
    vcx.simulate_keystrokes("down escape");
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("icon-picker").is_none(), "closed");
    assert!(
        title_focused(&main, &mut vcx),
        "focus is back on the title field"
    );
    state.read_with(&vcx, |s, _| {
        assert!(s.is_editing());
        assert!(!s.edit_buffer().unwrap().has_changes());
    });
}

#[gpui::test]
fn unknown_icon_kind_survives_picker_esc_and_cancel_untouched(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new("Future", device, 10);
    let mut future = vault_core::ItemIcon::new("hologram", "spin:3");
    future.color = Some("#123456".into());
    item.icon = Some(future.clone());
    let id = insert_and_select(&state, item, &mut vcx);
    state.update(&mut vcx, |s, _| s.vault.as_mut().unwrap().save().unwrap());
    vcx.run_until_parked();
    let file = dir.path().join("t.vault").join(vault_sync::VAULT_FILE_NAME);
    let bytes_before = std::fs::read(&file).unwrap();
    let (stored_before, modified_before) = state.read_with(&vcx, |s, _| {
        let it = s.unlocked_vault().unwrap().get(id).unwrap();
        (it.icon.clone(), it.modified_at)
    });
    assert_eq!(stored_before.as_ref(), Some(&future));

    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let tile = vcx.debug_bounds("edit-icon").unwrap();
    vcx.simulate_click(tile.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("icon-picker").is_some());
    vcx.simulate_keystrokes("escape");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().expect("Esc in the picker keeps editing");
        assert_eq!(b.item.icon.as_ref(), Some(&future));
        assert!(!b.has_changes(), "opening and closing is not a change");
    });
    let cancel = vcx.debug_bounds("cancel-edit");
    match cancel {
        Some(b) => vcx.simulate_click(b.center(), gpui::Modifiers::none()),
        None => vcx.dispatch_action(crate::actions::CancelEdit),
    }
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(!s.is_editing());
        assert!(s.discard_prompt.is_none(), "nothing to discard");
        let it = s.unlocked_vault().unwrap().get(id).unwrap();
        assert_eq!(it.icon, stored_before, "icon identical");
        assert_eq!(it.modified_at, modified_before, "no change recorded");
        assert!(!s.vault.as_ref().unwrap().is_dirty(), "nothing to save");
    });
    assert_eq!(
        std::fs::read(&file).unwrap(),
        bytes_before,
        "file untouched"
    );
}

#[gpui::test]
fn image_icon_draws_and_falls_back_to_automatic(cx: &mut TestAppContext) {
    use crate::icon_image::test_images::png;
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new("Bank", device, 10);
    item.fields = vec![vault_core::Field::new(
        "url",
        FieldKind::Url,
        SecretString::new("https://github.com".into()),
        10,
    )];
    let id = insert_and_select(&state, item, &mut vcx);

    // Chosen through the drop target on the edit tile.
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let path = dir.path().join("bank.png");
    std::fs::write(&path, png(40, 20, [0, 90, 200, 255])).unwrap();
    let tile = vcx.debug_bounds("edit-icon").unwrap().center();
    let paths = gpui::ExternalPaths(vec![path].into());
    vcx.simulate_event(gpui::FileDropEvent::Entered {
        position: tile,
        paths,
    });
    vcx.simulate_event(gpui::FileDropEvent::Submit { position: tile });
    vcx.run_until_parked();
    let a = state.read_with(&vcx, |s, _| {
        *s.edit_buffer()
            .unwrap()
            .icon_added
            .first()
            .expect("the drop on the tile chose the image")
    });
    let shown: &'static str = Box::leak(format!("icon-tile image {a}").into_boxed_str());
    assert!(
        vcx.debug_bounds(shown).is_some(),
        "edit tile shows the image"
    );
    // Not added as an ordinary attachment by the detail column's drop handler.
    let refs = state.read_with(&vcx, |s, _| {
        s.unlocked_vault()
            .unwrap()
            .get(id)
            .unwrap()
            .attachments
            .len()
    });
    assert_eq!(refs, 1);
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    assert!(vcx.debug_bounds(shown).is_some(), "list row and header");

    // Damage the blob and lock/unlock: the decode fails, the automatic letter shows.
    let store = crate::state::attachments_fake();
    state.update(&mut vcx, |s, cx| {
        s.set_attachment_store(store.clone());
        store.blobs.lock().unwrap().insert(a, b"not a png".to_vec());
        s.lock(cx);
        s.unlock(SecretString::new(PW.into()), cx);
    });
    vcx.run_until_parked();
    state.update(&mut vcx, |s, cx| s.select(id, cx));
    vcx.run_until_parked();
    assert!(vcx.debug_bounds(shown).is_none(), "no broken tile");
    let auto = state.read_with(&vcx, |s, _| {
        crate::icon::automatic(s.selected_item().unwrap()).describe()
    });
    assert!(auto.starts_with("letter B "), "{auto}");
    assert!(
        vcx.debug_bounds(leak(format!("icon-tile {auto} fill white")))
            .is_some(),
        "automatic icon instead"
    );
}

#[gpui::test]
fn icon_blob_is_hidden_from_the_attachments_section(cx: &mut TestAppContext) {
    use crate::state::AttachmentStore as _;
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let store = crate::state::attachments_fake();
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let id = insert_and_select(&state, vault_core::Item::new("Bank", device, 10), &mut vcx);
    state.update(&mut vcx, |s, cx| {
        s.set_attachment_store(store.clone());
        let vault = s.vault.as_mut().unwrap();
        let icon = store
            .add(vault, id, "icon.png", &mut &b"png"[..], 3, 11)
            .unwrap();
        vault
            .edit(|v| v.update(id, 12, |it| it.icon = Some(crate::icon::image_icon(icon))))
            .unwrap()
            .unwrap();
        s.vault_changed();
        cx.notify();
    });
    vcx.run_until_parked();
    // Only the icon blob: no section at all in read mode.
    assert!(vcx.debug_bounds("attachments-section").is_none());
    state.update(&mut vcx, |s, cx| {
        let vault = s.vault.as_mut().unwrap();
        store
            .add(vault, id, "scan.pdf", &mut &b"pdf"[..], 3, 13)
            .unwrap();
        s.vault_changed();
        cx.notify();
    });
    vcx.run_until_parked();
    assert!(
        vcx.debug_bounds("attachment-row scan.pdf 3 B Present")
            .is_some()
    );
    assert!(
        vcx.debug_bounds("attachment-row icon.png 3 B Present")
            .is_none()
    );
    // Edit mode lists the same.
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    assert!(
        vcx.debug_bounds("attachment-row scan.pdf 3 B Present")
            .is_some()
    );
    assert!(
        vcx.debug_bounds("attachment-row icon.png 3 B Present")
            .is_none()
    );
    // Remove, Preview and Save refuse the icon blob even by id.
    let icon = state.read_with(&vcx, |s, _| {
        let it = s.unlocked_vault().unwrap().get(id).unwrap();
        crate::icon::image_attachment(it.icon.as_ref().unwrap()).unwrap()
    });
    state.update(&mut vcx, |s, cx| {
        s.request_remove_attachment(icon, cx);
        assert!(s.attachments.remove_confirm.is_none());
        s.toggle_attachment_preview(icon, cx);
        assert!(s.attachments.reading.is_none() && s.attachments.preview.is_none());
    });
}

#[gpui::test]
fn choose_image_row_takes_a_drop_and_the_picker_stays_open(cx: &mut TestAppContext) {
    use crate::icon_image::{MAX_INPUT_BYTES, Refusal, test_images::png};
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let id = insert_and_select(&state, vault_core::Item::new("Bank", device, 10), &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let tile = vcx.debug_bounds("edit-icon").unwrap();
    vcx.simulate_click(tile.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    let row = vcx.debug_bounds("icon-picker-image").expect("row").center();

    let drop_on_row = |path: std::path::PathBuf, vcx: &mut VisualTestContext| {
        vcx.simulate_event(gpui::FileDropEvent::Entered {
            position: row,
            paths: gpui::ExternalPaths(vec![path].into()),
        });
        vcx.simulate_event(gpui::FileDropEvent::Pending { position: row });
        vcx.run_until_parked();
        // A drag entering is not an outside mouse-down: the popover stays.
        assert!(
            vcx.debug_bounds("icon-picker").is_some(),
            "open while dragging"
        );
        vcx.simulate_event(gpui::FileDropEvent::Submit { position: row });
        vcx.run_until_parked();
    };

    // Same refusal as the tile: over 512 KB.
    let big = dir.path().join("big.png");
    let mut bytes = png(4, 4, [0, 0, 0, 255]);
    bytes.resize(MAX_INPUT_BYTES as usize + 1, 0);
    std::fs::write(&big, bytes).unwrap();
    drop_on_row(big, &mut vcx);
    state.read_with(&vcx, |s, _| {
        assert_eq!(
            s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
            Some(Refusal::TooLarge.message())
        );
        assert!(s.edit_buffer().unwrap().icon_added.is_empty());
    });

    // Same prepare path as the tile: a 128 px PNG becomes the icon, picker still open.
    let ok = dir.path().join("logo.png");
    std::fs::write(&ok, png(300, 100, [10, 20, 30, 255])).unwrap();
    drop_on_row(ok, &mut vcx);
    let a = state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        assert!(b.icon_picker.is_some(), "picker still open after the drop");
        assert_eq!(b.icon_added.len(), 1);
        b.icon_added[0]
    });
    assert!(vcx.debug_bounds("icon-picker").is_some());
    let item = state.read_with(&vcx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().clone()
    });
    assert_eq!(
        item.attachments.len(),
        1,
        "not also added as an ordinary attachment"
    );
    assert_eq!(item.attachments[0].id, a);
    assert_eq!(item.attachments[0].name, crate::icon_image::ATTACHMENT_NAME);
}

/// The name input of row `key`.
pub(super) fn name_input(
    main: &Entity<MainScreen>,
    key: u64,
    vcx: &mut VisualTestContext,
) -> Entity<InputState> {
    main.read_with(vcx, |m, cx| {
        m.editor
            .read(cx)
            .rows
            .iter()
            .find(|r| r.key == key)
            .expect("row")
            .name
            .clone()
    })
}

/// Selects all of `input` and types `text` one character at a time.
fn retype(input: &Entity<InputState>, text: &str, vcx: &mut VisualTestContext) {
    vcx.update(|window, cx| ui::focus_input(input, window, cx));
    vcx.simulate_keystrokes("cmd-a");
    for c in text.chars() {
        vcx.simulate_input(&c.to_string());
    }
    vcx.run_until_parked();
}

/// A field added in edit mode gets its name's first character capitalised as it is
/// typed; the rest stays as typed, the user can lowercase it again, and existing field
/// names and values are left alone.
#[gpui::test]
fn new_field_names_start_with_a_capital(cx: &mut TestAppContext) {
    assert_eq!(super::capitalize_first("gpg passphrase"), "Gpg passphrase");
    assert_eq!(super::capitalize_first("ärger"), "Ärger");
    assert_eq!(super::capitalize_first(""), "");

    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, "Box".into(), cx)
    });
    vcx.run_until_parked();
    vcx.simulate_keystrokes("cmd-s");
    vcx.simulate_keystrokes("cmd-e");
    vcx.run_until_parked();
    let existing = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys[0]);
    let key = state.update(&mut vcx, |s, cx| {
        let mut key = 0;
        s.edit(cx, |b| key = b.add_field(FieldKind::Text));
        key
    });
    vcx.run_until_parked();

    // Capitalised from the moment it appears: the pre-filled name, in the buffer and
    // the input. The template's own names keep their spelling.
    let name = name_input(&main, key, &mut vcx);
    assert_eq!(vcx.update(|_, cx| ui::input_text(&name, cx)), "Text");
    state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        assert_eq!(b.field(key).unwrap().name, "Text");
        assert_eq!(b.field(existing).unwrap().name, "Username");
    });
    retype(&name, "gpg passphrase", &mut vcx);
    assert_eq!(
        vcx.update(|_, cx| ui::input_text(&name, cx)),
        "Gpg passphrase"
    );
    let buffer_name = |vcx: &mut VisualTestContext| {
        state.read_with(vcx, |s, _| {
            s.edit_buffer().unwrap().field(key).unwrap().name.clone()
        })
    };
    assert_eq!(buffer_name(&mut vcx), "Gpg passphrase");

    // The user can lowercase it again: no second capitalisation.
    retype(&name, "pin", &mut vcx);
    assert_eq!(buffer_name(&mut vcx), "pin");

    // The new field's value and an existing field's name are left as typed.
    let value = value_input(&main, key, &mut vcx);
    type_into(&value, "lower", &mut vcx);
    assert_eq!(vcx.update(|_, cx| ui::input_text(&value, cx)), "lower");
    let old = name_input(&main, existing, &mut vcx);
    retype(&old, "login", &mut vcx);
    assert_eq!(vcx.update(|_, cx| ui::input_text(&old, cx)), "login");

    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        let names: Vec<_> = s
            .selected_item()
            .unwrap()
            .fields
            .iter()
            .map(|f| f.name.clone())
            .collect();
        assert!(names.contains(&"pin".to_owned()), "{names:?}");
        assert!(names.contains(&"login".to_owned()), "{names:?}");
    });
}

/// Opens the icon picker on a new item titled `title` with optional website `url`.
fn picker_on(
    title: &str,
    url: Option<&str>,
    cx: &mut TestAppContext,
) -> (tempfile::TempDir, Entity<AppState>, VisualTestContext, u32) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new(title, device, 10);
    if let Some(url) = url {
        item.fields = vec![vault_core::Field::new(
            "url",
            FieldKind::Url,
            SecretString::new(url.into()),
            10,
        )];
    }
    insert_and_select(&state, item, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let tile = vcx.debug_bounds("edit-icon").unwrap();
    vcx.simulate_click(tile.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    let default = state.read_with(&vcx, |s, _| {
        crate::icon::palette_color(&s.edit_buffer().unwrap().item)
    });
    (dir, state, vcx, default)
}

pub(super) fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn click(vcx: &mut VisualTestContext, selector: String) {
    let b = vcx.debug_bounds(leak(selector)).expect("on screen");
    vcx.simulate_click(b.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
}

#[gpui::test]
fn picker_shape_and_colour_are_independent(cx: &mut TestAppContext) {
    use crate::icon::PALETTE;
    let (_dir, state, mut vcx, default) = picker_on("Wallet", None, cx);
    let def_ix = PALETTE.iter().position(|c| *c == default).unwrap();
    let x_ix = (def_ix + 1) % PALETTE.len();
    // Opening: Automatic selected, the default colour selected, no default marker; the
    // Automatic row previews the letter in the default colour.
    let preview = |c: u32| leak(format!("icon-auto-preview letter W #{c:06X}"));
    assert!(vcx.debug_bounds(preview(default)).is_some());
    assert!(vcx.debug_bounds("icon-auto-selected").is_some());
    assert!(
        vcx.debug_bounds(leak(format!("icon-color-chosen {def_ix}")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds(leak(format!("icon-color-default {def_ix}")))
            .is_none()
    );
    assert!(vcx.debug_bounds("icon-color-disabled").is_none());

    // A colour pick keeps Automatic selected; the header tile follows live.
    click(&mut vcx, format!("icon-color {x_ix}"));
    assert!(
        vcx.debug_bounds("icon-auto-selected").is_some(),
        "Automatic stays"
    );
    assert!(
        vcx.debug_bounds(preview(PALETTE[x_ix])).is_some(),
        "row preview follows"
    );
    assert!(
        vcx.debug_bounds(leak(format!("icon-color-chosen {x_ix}")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds(leak(format!(
            "icon-tile letter W #{:06X} fill white",
            PALETTE[x_ix]
        )))
        .is_some(),
        "header tile preview"
    );
    // Back to the default colour clears the override entirely.
    click(&mut vcx, format!("icon-color {def_ix}"));
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.edit_buffer().unwrap().item.icon, None)
    });

    // A colour on a symbol is previewed by the Automatic row too (what picking it gives).
    click(&mut vcx, "icon-symbol 2".into());
    click(&mut vcx, format!("icon-color {x_ix}"));
    assert!(vcx.debug_bounds(preview(PALETTE[x_ix])).is_some());
    click(&mut vcx, format!("icon-color {def_ix}"));
    assert!(vcx.debug_bounds(preview(default)).is_some());

    // A symbol: Automatic deselects, the default colour shows selected.
    click(&mut vcx, "icon-symbol 4".into());
    assert!(vcx.debug_bounds("icon-auto-selected").is_none());
    assert!(vcx.debug_bounds("icon-symbol-chosen 4").is_some());
    assert!(
        vcx.debug_bounds(leak(format!("icon-color-chosen {def_ix}")))
            .is_some()
    );
    state.read_with(&vcx, |s, _| {
        let i = s.edit_buffer().unwrap().item.icon.clone().unwrap();
        assert_eq!((i.kind.as_str(), i.color), ("symbol", None));
    });
}

#[gpui::test]
fn non_image_files_are_refused_on_drop(cx: &mut TestAppContext) {
    // gpui 0.3.10's open panel has no file-type filter, so a PDF can be chosen or
    // dropped; the magic-byte check refuses it with the same toast either way.
    let (_dir, state, mut vcx, _) = picker_on("Scan", None, cx);
    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("scan.pdf");
    std::fs::write(&pdf, b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n").unwrap();
    let row = vcx.debug_bounds("icon-picker-image").unwrap().center();
    vcx.simulate_event(gpui::FileDropEvent::Entered {
        position: row,
        paths: gpui::ExternalPaths(vec![pdf].into()),
    });
    vcx.simulate_event(gpui::FileDropEvent::Submit { position: row });
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert_eq!(
            s.toast.as_ref().map(|t| t.message.to_string()).as_deref(),
            Some(crate::icon_image::Refusal::Unreadable.message())
        );
        let b = s.edit_buffer().unwrap();
        assert!(b.icon_added.is_empty() && b.item.icon.is_none());
        let id = b.item.id;
        assert!(
            s.unlocked_vault()
                .unwrap()
                .get(id)
                .unwrap()
                .attachments
                .is_empty()
        );
    });
}

#[gpui::test]
fn adding_a_section_writes_a_heading_with_no_value(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let id = insert_and_select(&state, vault_core::Item::new("Bank", device, 10), &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    assert!(
        ADDABLE_KINDS.contains(&FieldKind::Section),
        "offered by Add field"
    );
    let key = state.update(&mut vcx, |s, cx| {
        let mut key = 0;
        s.edit(cx, |b| key = b.add_field(FieldKind::Section));
        key
    });
    vcx.run_until_parked();
    // Name pre-filled "Section", placeholder "Section name", chip "Section", no value.
    let name = name_input(&main, key, &mut vcx);
    assert_eq!(vcx.update(|_, cx| ui::input_text(&name, cx)), "Section");
    let placeholder = vcx.update(|_, cx| name.read(cx).presentation().placeholder().to_string());
    assert_eq!(placeholder, "Section name");
    assert_eq!(kind_name(FieldKind::Section), "Section");
    main.read_with(&vcx, |m, cx| {
        let editor = m.editor.read(cx);
        let row = editor.rows.iter().find(|r| r.key == key).unwrap();
        assert!(matches!(row.value, ValueInput::None), "no value input");
    });
    retype(&name, "login details", &mut vcx);
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    let field = state.read_with(&vcx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().fields[0].clone()
    });
    assert_eq!(field.kind, FieldKind::Section);
    assert_eq!(
        field.name, "Login details",
        "auto-capitalised like any new field"
    );
    assert_eq!(field.value.expose_secret(), "");
    assert!(vcx.debug_bounds("section-row 0 LOGIN DETAILS").is_some());
}

/// A crafted vault can store any value on a Section (core keeps it as given, and a
/// Section is never sensitive). It must never be drawn, copied, revealed or picked by a
/// name lookup. gpui test windows expose no text dump, so this checks every element
/// that draws a field value (value cells, masked cells, editor inputs) plus the copy,
/// subtitle, card-masking and logo paths.
#[gpui::test]
fn section_values_never_surface(cx: &mut TestAppContext) {
    const SECRET: &str = "SHOULD-NOT-SHOW";
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let board = crate::clipboard::fake::FakePasteboard::default();
    let device = state.read_with(&vcx, |s, _| s.device_id());
    state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board.clone())));
    let section = |name: &str, value: &str| {
        vault_core::Field::new(
            name,
            FieldKind::Section,
            SecretString::new(value.into()),
            10,
        )
    };
    let mut crafted = vault_core::Item::new("Crafted", device, 10);
    crafted.fields = vec![
        section("Username", SECRET),
        section("Website", "https://github.com"),
        vault_core::Field::new(
            "note",
            FieldKind::Text,
            SecretString::new("visible".into()),
            10,
        ),
    ];
    let mut card = crate::templates::tagged(crate::templates::Template::Card, "Visa", device, 10);
    card.fields = vec![section("Number", "4242424242424242")];
    let card_id = insert_and_select(&state, card, &mut vcx);
    let id = insert_and_select(&state, crafted, &mut vcx);

    // Read mode: headings only; no value cell for either section.
    assert!(vcx.debug_bounds("section-row 0 USERNAME").is_some());
    assert!(vcx.debug_bounds("section-row 1 WEBSITE").is_some());
    for ix in 0..2 {
        for what in ["field-value", "field-masked", "field-row", "copy", "reveal"] {
            let key: &'static str = Box::leak(format!("{what} {ix}").into_boxed_str());
            assert!(vcx.debug_bounds(key).is_none(), "{key}");
        }
    }
    assert!(
        vcx.debug_bounds("field-value 2").is_some(),
        "the real field shows"
    );

    state.update(&mut vcx, |s, cx| {
        let item = s.selected_item().unwrap().clone();
        // Name lookups skip sections: not the subtitle or ⌘⇧U.
        assert_eq!(crate::listing::subtitle(&item), "");
        assert!(crate::listing::username_field(&item).is_none());
        // Copy targets: ⌘⇧U and copy-by-index copy nothing.
        s.copy(crate::state::CopyTarget::Username, cx);
        s.copy(crate::state::CopyTarget::Field(item.fields[0].id), cx);
        // A section named "Number" on a card is not masked as a card number.
        let card = s.unlocked_vault().unwrap().get(card_id).unwrap().clone();
        assert!(!crate::listing::is_card_number(&card, &card.fields[0]));
        assert_ne!(
            crate::listing::subtitle(&card),
            "\u{2022}\u{2022}\u{2022}\u{2022} 4242"
        );
    });
    assert_eq!(board.contents(), None, "nothing copied");

    // Item window: same rows.
    let handle = vcx
        .cx
        .update(|cx| crate::screens::open_item_window(state.clone(), id, cx))
        .unwrap();
    let mut win = VisualTestContext::from_window(handle, &vcx.cx);
    win.run_until_parked();
    assert!(win.debug_bounds("section-row 0 USERNAME").is_some());
    assert!(win.debug_bounds("field-value 0").is_none());
    assert!(win.debug_bounds("field-value 2").is_some());

    // Edit mode: no editor input holds the value.
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let texts: Vec<String> = main.read_with(&vcx, |m, cx| {
        let editor = m.editor.read(cx);
        editor
            .rows
            .iter()
            .flat_map(|r| {
                let mut t = vec![ui::input_text(&r.name, cx)];
                match &r.value {
                    ValueInput::Line(i) => t.push(ui::input_text(i, cx)),
                    ValueInput::Area(a) => {
                        t.push(ui::textarea_secret(a, cx).expose_secret().to_owned())
                    }
                    ValueInput::None => {}
                }
                t
            })
            .collect()
    });
    assert_eq!(texts.len(), 4, "two names, one name, one name + value");
    assert!(texts.iter().all(|t| !t.contains(SECRET)), "{texts:?}");
}

/// Pasting 1 MiB + 1 byte into Notes keeps exactly 1 MiB, says so next to the field, and
/// Save still works and stores the kept text.
#[gpui::test]
fn pasted_note_over_the_field_limit_is_cut_and_saves(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Note, "Big".into(), cx)
    });
    vcx.run_until_parked();
    let key = state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        let ix = b
            .item
            .fields
            .iter()
            .position(|f| f.kind == FieldKind::Notes)
            .expect("note template has a Notes field");
        b.keys[ix]
    });
    let area = main.read_with(&vcx, |m, cx| {
        match &m
            .editor
            .read(cx)
            .rows
            .iter()
            .find(|r| r.key == key)
            .unwrap()
            .value
        {
            ValueInput::Area(a) => a.clone(),
            _ => panic!("notes edit in a text area"),
        }
    });
    let limit = EditBuffer::FIELD_LIMIT_BYTES;
    let selector = format!("field-limit {key}");
    let selector: &'static str = Box::leak(selector.into_boxed_str());
    assert!(
        vcx.debug_bounds(selector).is_none(),
        "no note before the paste"
    );
    vcx.update(|window, cx| {
        area.update(cx, |a, cx| a.focus(window, cx));
        cx.write_to_clipboard(gpui::ClipboardItem::new_string("n".repeat(limit + 1)));
    });
    vcx.simulate_keystrokes("cmd-v");
    vcx.run_until_parked();

    assert!(
        vcx.debug_bounds(selector).is_some(),
        "inline limit note shown"
    );
    let shown = area.read_with(&vcx, |a, _| a.text().len());
    assert_eq!(shown, limit, "the text area holds only the kept text");
    // Save is never disabled by the limit: ⌘S saves the kept text.
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(!s.is_editing(), "saved");
        let item = s.selected_item().unwrap();
        let notes = item
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Notes)
            .unwrap();
        assert_eq!(
            notes.value.expose_secret().len(),
            limit,
            "stored exactly 1 MiB"
        );
    });
}

/// Key down and up: a focused row's keyboard click fires on key up.
pub(super) fn press(vcx: &mut VisualTestContext, key: &'static str) {
    vcx.simulate_keystrokes(key);
    vcx.simulate_event(gpui::KeyUpEvent {
        keystroke: gpui::Keystroke::parse(key).unwrap(),
    });
    vcx.run_until_parked();
}

fn sort_checked(vcx: &mut VisualTestContext) -> (bool, bool) {
    (
        vcx.debug_bounds("sort-name-checked").is_some(),
        vcx.debug_bounds("sort-modified-checked").is_some(),
    )
}

#[gpui::test]
fn sort_menu_opens_by_click_and_closes_on_esc(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    click(&mut vcx, "sort".into());
    assert!(state.read_with(&vcx, |s, _| s.sort_menu_open));
    assert_eq!(sort_checked(&mut vcx), (true, false));
    press(&mut vcx, "escape");
    assert!(!state.read_with(&vcx, |s, _| s.sort_menu_open));
    assert!(vcx.debug_bounds("sort-name").is_none(), "menu gone");
}

/// Keyboard: focus the Sort button, Space opens with the first row focused; ↓ Enter
/// picks Recently Modified, and reopening shows the check mark moved.
#[gpui::test]
fn sort_menu_by_keyboard_switches_order(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    // A click opens the menu, so reach Sort by key. The list column's buttons follow
    // the detail column in Tab order (05 §6): back from the first sidebar row, the
    // ring wraps through New and the generator to Sort.
    let all = vcx.debug_bounds("nav All Items icon=LayoutList").unwrap();
    vcx.simulate_click(all.center(), gpui::Modifiers::none());
    vcx.run_until_parked();
    for _ in 0..3 {
        press(&mut vcx, "shift-tab");
    }
    assert!(
        vcx.update(|w, cx| main.read(cx).sort_focus.is_focused(w)),
        "three Shift-Tabs reach the Sort button (a new toolbar button moves it)"
    );
    press(&mut vcx, "space");
    assert!(state.read_with(&vcx, |s, _| s.sort_menu_open));
    press(&mut vcx, "down");
    press(&mut vcx, "enter");
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.sort, crate::state::Sort::RecentlyModified);
        assert!(!s.sort_menu_open, "a pick closes the menu");
    });
    state.update(&mut vcx, |s, cx| s.open_sort_menu(cx));
    vcx.run_until_parked();
    assert_eq!(sort_checked(&mut vcx), (false, true));
    state.update(&mut vcx, |s, cx| s.lock(cx));
    vcx.run_until_parked();
    assert!(
        !state.read_with(&vcx, |s, _| s.sort_menu_open),
        "lock closes"
    );
}

#[gpui::test]
fn add_field_menu_adds_the_first_kind_and_closes(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    insert_and_select(&state, vault_core::Item::new("Bank", device, 1), &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let fields = |vcx: &VisualTestContext| {
        state.read_with(vcx, |s, _| s.edit_buffer().unwrap().item.fields.len())
    };
    let before = fields(&vcx);

    click(&mut vcx, "add-field".into());
    assert!(state.read_with(&vcx, |s, _| s.add_field_menu_open));
    press(&mut vcx, "escape");
    assert!(!state.read_with(&vcx, |s, _| s.add_field_menu_open), "Esc");
    // Esc closed the menu first; the edit itself is still open.
    assert!(
        state.read_with(&vcx, |s, _| s.is_editing()),
        "Esc keeps editing"
    );

    // From app state, as after a key press: the first row has focus.
    vcx.simulate_keystrokes("shift");
    state.update(&mut vcx, |s, cx| s.open_add_field_menu(cx));
    vcx.run_until_parked();
    press(&mut vcx, "enter");
    state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        assert_eq!(b.item.fields.len(), before + 1);
        assert_eq!(b.item.fields.last().unwrap().kind, ADDABLE_KINDS[0]);
        assert!(!s.add_field_menu_open, "a pick closes the menu");
    });
    assert!(vcx.debug_bounds("add-field-text").is_none(), "menu gone");

    state.update(&mut vcx, |s, cx| s.open_add_field_menu(cx));
    vcx.run_until_parked();
    state.update(&mut vcx, |s, cx| s.cancel_edit(cx));
    assert!(
        !state.read_with(&vcx, |s, _| s.add_field_menu_open),
        "Cancel"
    );
    state.update(&mut vcx, |s, cx| {
        s.begin_edit(cx);
        s.open_add_field_menu(cx);
        s.lock(cx);
    });
    assert!(!state.read_with(&vcx, |s, _| s.add_field_menu_open), "lock");
}

/// Picks `kind` from the real "Add field" menu with the pointer; returns the new row's key.
fn add_field_by_click(state: &Entity<AppState>, vcx: &mut VisualTestContext, kind: &str) -> u64 {
    click(vcx, "add-field".into());
    click(vcx, format!("add-field-{kind}"));
    state.read_with(vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        assert_eq!(b.focus_row, None, "pending focus consumed");
        *b.keys.last().unwrap()
    })
}

fn focused(input: &Entity<InputState>, vcx: &mut VisualTestContext) -> bool {
    vcx.update(|window, cx| gpui::Focusable::focus_handle(input, cx).is_focused(window))
}

/// 05 §2.5 (owner 2026-11-12): an added field is scrolled into view and its Value input
/// takes focus; its default name is kept.
#[gpui::test]
fn added_field_is_revealed_and_its_value_focused(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new("Long", device, 1);
    item.fields = (0..40)
        .map(|i| {
            let v = SecretString::new("v".into());
            vault_core::Field::new(format!("f{i}"), FieldKind::Text, v, 1)
        })
        .collect();
    insert_and_select(&state, item, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let viewport = vcx.update(|window, _| window.viewport_size());
    let last = state.read_with(&vcx, |s, _| *s.edit_buffer().unwrap().keys.last().unwrap());
    let off = |vcx: &mut VisualTestContext, key: u64| {
        let b = vcx.debug_bounds(leak(format!("edit-row {key}")));
        b.is_none_or(|b| b.bottom() > viewport.height)
    };
    assert!(off(&mut vcx, last), "the last row starts below the fold");

    // "Add field" is below the fold too: open the menu by keyboard, Enter picks Text.
    vcx.simulate_keystrokes("shift");
    state.update(&mut vcx, |s, cx| s.open_add_field_menu(cx));
    vcx.run_until_parked();
    press(&mut vcx, "enter");
    let key = state.read_with(&vcx, |s, _| *s.edit_buffer().unwrap().keys.last().unwrap());
    let value = value_input(&main, key, &mut vcx);
    assert!(focused(&value, &mut vcx), "value input focused");
    assert!(!off(&mut vcx, key), "new row scrolled into view");
    let name = state.read_with(&vcx, |s, _| {
        s.edit_buffer()
            .unwrap()
            .item
            .fields
            .last()
            .unwrap()
            .name
            .clone()
    });
    assert_eq!(name, "Text", "default name unchanged");
}

#[gpui::test]
fn added_section_focuses_its_title(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    insert_and_select(&state, vault_core::Item::new("Bank", device, 1), &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let key = add_field_by_click(&state, &mut vcx, "section");
    let name = name_input(&main, key, &mut vcx);
    assert!(focused(&name, &mut vcx), "section title focused");
}

#[gpui::test]
fn adding_fields_in_a_run_focuses_the_latest(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    insert_and_select(&state, vault_core::Item::new("Bank", device, 1), &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let first = add_field_by_click(&state, &mut vcx, "text");
    let second = add_field_by_click(&state, &mut vcx, "url");
    let (first, second) = (
        value_input(&main, first, &mut vcx),
        value_input(&main, second, &mut vcx),
    );
    assert!(focused(&second, &mut vcx), "second value focused");
    assert!(!focused(&first, &mut vcx));
}

#[gpui::test]
fn deleting_while_editing_closes_the_add_field_menu(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let id = insert_and_select(&state, vault_core::Item::new("Bank", device, 1), &mut vcx);
    state.update(&mut vcx, |s, cx| {
        s.begin_edit(cx);
        s.open_add_field_menu(cx);
    });
    vcx.run_until_parked();
    assert!(state.read_with(&vcx, |s, _| s.add_field_menu_open));
    state.update(&mut vcx, |s, cx| {
        s.delete_confirm = Some(id);
        s.confirm_delete(cx);
    });
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(!s.is_editing(), "the delete ended the edit");
        assert!(!s.add_field_menu_open, "and closed the menu");
    });
}

/// An item with a text field, a section and a password, inserted at stamp 10 and in
/// edit mode; returns the item id and the three row keys.
fn editing_with_section(state: &Entity<AppState>, vcx: &mut VisualTestContext) -> (Uuid, [u64; 3]) {
    let device = state.read_with(vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new("Bank", device, 10);
    let field =
        |name: &str, kind| vault_core::Field::new(name, kind, SecretString::new("v".into()), 10);
    item.fields = vec![
        field("user", FieldKind::Text),
        field("Extras", FieldKind::Section),
        field("password", FieldKind::Password),
    ];
    let id = insert_and_select(state, item, vcx);
    state.update(vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    (id, [keys[0], keys[1], keys[2]])
}

fn name_focused(main: &Entity<MainScreen>, key: u64, vcx: &mut VisualTestContext) -> bool {
    let name = name_input(main, key, vcx);
    vcx.update(|window, cx| gpui::Focusable::focus_handle(&name, cx).is_focused(window))
}

fn field_icon(state: &Entity<AppState>, key: u64, vcx: &VisualTestContext) -> Option<String> {
    state.read_with(vcx, |s, _| {
        s.edit_buffer().unwrap().field(key).unwrap().icon.clone()
    })
}

/// 05 "Field icons": the button opens "No icon" + the shared grid; a pick is part of
/// the edit (dirty, guarded), closes the picker, and Save writes and restamps the field.
#[gpui::test]
fn field_icon_pick_saves_and_restamps(cx: &mut TestAppContext) {
    use crate::icon::SYMBOLS;
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let (id, [user, section, password]) = editing_with_section(&state, &mut vcx);
    let other = state.update(&mut vcx, |s, _| {
        let device = s.device_id();
        let id = s
            .vault
            .as_mut()
            .unwrap()
            .edit(|v| v.insert(vault_core::Item::new("Other", device, 1), 1))
            .unwrap();
        s.vault_changed();
        id
    });
    vcx.run_until_parked();
    // Buttons on field rows only, showing the placeholder.
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-button {user} none")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-button {password} none")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-button {section} none")))
            .is_none(),
        "no icon control on a section row"
    );
    state.update(&mut vcx, |s, cx| s.set_field_icon_picker(section, true, cx));
    assert_eq!(state.read_with(&vcx, |s, _| s.field_icon_picker()), None);

    click(&mut vcx, format!("field-icon-button {user} none"));
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-picker {user}")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-none {user}-checked")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds("field-icon-symbol 39").is_some(),
        "40 symbols"
    );
    let key_ix = SYMBOLS.iter().position(|(n, ..)| *n == "KeyRound").unwrap();
    click(&mut vcx, format!("field-icon-symbol {key_ix}"));
    assert_eq!(field_icon(&state, user, &vcx).as_deref(), Some("KeyRound"));
    assert!(
        state.read_with(&vcx, |s, _| s.field_icon_picker().is_none()),
        "a pick closes"
    );
    assert!(
        name_focused(&main, user, &mut vcx),
        "focus back on the name"
    );
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-button {user} KeyRound")))
            .is_some()
    );

    // Icon-only change: dirty, so leaving asks first.
    assert!(state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().has_changes()));
    state.update(&mut vcx, |s, cx| s.select(other, cx));
    assert!(
        state.read_with(&vcx, |s, _| s.discard_prompt.is_some()),
        "guarded"
    );
    state.update(&mut vcx, |s, cx| s.cancel_edit(cx));
    assert!(state.read_with(&vcx, |s, _| s.is_editing()));

    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    let item = state.read_with(&vcx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().clone()
    });
    assert_eq!(item.fields[0].icon.as_deref(), Some("KeyRound"));
    assert!(item.fields[0].modified_at > 10, "restamped");
    assert_eq!(
        item.fields[2].modified_at, 10,
        "untouched field keeps its stamp"
    );
    assert_eq!(item.fields[2].icon, None);
    assert!(
        vcx.debug_bounds("field-row-icon 0 KeyRound").is_some(),
        "read mode shows it"
    );
}

/// Keyboard: ↓ leaves "No icon" for the grid, → moves, Enter picks; Esc closes and
/// focuses the name input; "No icon" clears; Cancel drops the choice; ending the edit
/// closes the picker.
#[gpui::test]
fn field_icon_picker_by_keyboard_no_icon_and_cancel(cx: &mut TestAppContext) {
    use crate::icon::SYMBOLS;
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let (id, [user, _, password]) = editing_with_section(&state, &mut vcx);
    click(&mut vcx, format!("field-icon-button {password} none"));
    vcx.simulate_keystrokes("down right enter");
    vcx.run_until_parked();
    assert_eq!(
        field_icon(&state, password, &vcx).as_deref(),
        Some(SYMBOLS[1].0)
    );
    assert!(name_focused(&main, password, &mut vcx));

    // Reopened on the choice; Esc from elsewhere returns focus to this row's name.
    let user_name = name_input(&main, user, &mut vcx);
    vcx.update(|window, cx| ui::focus_input(&user_name, window, cx));
    click(
        &mut vcx,
        format!("field-icon-button {password} {:?}", SYMBOLS[1].1),
    );
    assert!(vcx.debug_bounds("field-icon-symbol-chosen 1").is_some());
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-none {password}-checked")))
            .is_none()
    );
    vcx.simulate_keystrokes("down escape");
    vcx.run_until_parked();
    assert!(
        state.read_with(&vcx, |s, _| s.field_icon_picker().is_none()),
        "Esc closes"
    );
    assert!(
        state.read_with(&vcx, |s, _| s.is_editing()),
        "and keeps editing"
    );
    assert!(
        name_focused(&main, password, &mut vcx),
        "focus on that row's name"
    );
    assert_eq!(
        field_icon(&state, password, &vcx).as_deref(),
        Some(SYMBOLS[1].0)
    );

    // "No icon" clears it again.
    click(
        &mut vcx,
        format!("field-icon-button {password} {:?}", SYMBOLS[1].1),
    );
    click(&mut vcx, format!("field-icon-none {password}"));
    assert_eq!(field_icon(&state, password, &vcx), None);
    assert!(!state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().has_changes()));

    // Cancel drops a choice; the stored field never had one.
    click(&mut vcx, format!("field-icon-button {user} none"));
    click(&mut vcx, "field-icon-symbol 0".into());
    state.update(&mut vcx, |s, cx| s.set_field_icon_picker(user, true, cx));
    state.update(&mut vcx, |s, cx| s.cancel_edit(cx));
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(
            s.field_icon_picker().is_none(),
            "ending the edit closes the picker"
        );
        let item = s.unlocked_vault().unwrap().get(id).unwrap();
        assert!(
            item.fields.iter().all(|f| f.icon.is_none()),
            "Cancel discards"
        );
        assert!(item.fields.iter().all(|f| f.modified_at == 10));
    });
    // Lock closes it too.
    state.update(&mut vcx, |s, cx| {
        s.begin_edit(cx);
        let key = s.edit_buffer().unwrap().keys[0];
        s.set_field_icon_picker(key, true, cx);
        assert!(s.field_icon_picker().is_some());
        s.lock(cx);
    });
    assert!(
        state.read_with(&vcx, |s, _| s.field_icon_picker().is_none()),
        "lock"
    );
}

/// Tab from the open picker reaches "No icon"; Enter or Space there clears the icon
/// like its click, not the keyboard cursor's cell (which sits on the chosen symbol).
#[gpui::test]
fn shift_tab_to_no_icon_then_enter_or_space_clears(cx: &mut TestAppContext) {
    use crate::icon::SYMBOLS;
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let (_, [_, _, password]) = editing_with_section(&state, &mut vcx);
    for key in ["enter", "space"] {
        click(&mut vcx, format!("field-icon-button {password} none"));
        click(&mut vcx, "field-icon-symbol 1".into());
        assert_eq!(
            field_icon(&state, password, &vcx).as_deref(),
            Some(SYMBOLS[1].0)
        );
        click(
            &mut vcx,
            format!("field-icon-button {password} {:?}", SYMBOLS[1].1),
        );
        assert!(vcx.debug_bounds("field-icon-symbol-chosen 1").is_some());
        let (search, none) = main.read_with(&vcx, |m, cx| {
            let e = m.editor.read(cx);
            let r = e.rows.iter().find(|r| r.key == password);
            (
                gpui::Focusable::focus_handle(&e.icon_search, cx),
                r.unwrap().icon_focus.none.clone(),
            )
        });
        assert!(
            vcx.update(|w, _| search.is_focused(w)),
            "the search field has the focus (05 \"Icon search\")"
        );
        press(&mut vcx, "shift-tab");
        assert!(
            vcx.update(|w, _| none.is_focused(w)),
            "Shift-Tab reaches \"No icon\" above it"
        );
        press(&mut vcx, key);
        assert_eq!(field_icon(&state, password, &vcx), None, "{key} clears");
        assert!(
            state.read_with(&vcx, |s, _| s.field_icon_picker().is_none()),
            "{key} closes"
        );
        assert!(
            name_focused(&main, password, &mut vcx),
            "{key}: focus on the name"
        );
    }
}

/// Removing the row whose picker is open closes it; a row's picker survives another
/// row's removal; a row gone from the buffer by any other path reads as closed.
#[gpui::test]
fn removing_a_row_closes_its_icon_picker(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(dir.path(), cx);
    let (_, [user, _, password]) = editing_with_section(&state, &mut vcx);
    click(&mut vcx, format!("field-icon-button {password} none"));
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-picker {password}")))
            .is_some()
    );
    state.update(&mut vcx, |s, cx| s.edit(cx, |b| b.remove_field(password)));
    vcx.run_until_parked();
    assert_eq!(state.read_with(&vcx, |s, _| s.field_icon_picker()), None);
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-picker {password}")))
            .is_none()
    );

    click(&mut vcx, format!("field-icon-button {user} none"));
    let section = state.update(&mut vcx, |s, cx| {
        let section = s.edit_buffer().unwrap().keys[1];
        s.edit(cx, |b| b.remove_field(section));
        section
    });
    assert_eq!(
        state.read_with(&vcx, |s, _| s.field_icon_picker().map(|(k, _)| k)),
        Some(user),
        "removing row {section} leaves row {user}'s picker open"
    );
    // Rows replaced without `edit` (a rebuild): the stale key is not an open picker.
    state.update(&mut vcx, |s, cx| {
        let b = s.edit_buffer_mut().unwrap();
        b.keys = b.keys.iter().map(|k| k + 100).collect();
        s.field_icon_picker_move(crate::icon::Move::Down, cx);
        s.field_icon_picker_choose(cx);
    });
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.field_icon_picker(), None);
        let b = s.edit_buffer().unwrap();
        assert!(b.item.fields.iter().all(|f| f.icon.is_none()), "no pick");
    });
}

/// A stored icon name this build does not know is kept through a rename and Save.
#[gpui::test]
fn unknown_field_icon_survives_rename_and_save(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new("Bank", device, 10);
    let mut pin = vault_core::Field::new("pin", FieldKind::Text, SecretString::new("1".into()), 10);
    pin.icon = Some("x-future-symbol".into());
    item.fields = vec![pin];
    let id = insert_and_select(&state, item, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let key = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys[0]);
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-button {key} none")))
            .is_some(),
        "unknown name shows the placeholder"
    );
    retype(&name_input(&main, key, &mut vcx), "PIN code", &mut vcx);
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    let field = state.read_with(&vcx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().fields[0].clone()
    });
    assert_eq!(field.name, "PIN code");
    assert!(field.modified_at > 10, "renamed and saved");
    assert_eq!(field.icon.as_deref(), Some("x-future-symbol"));
}

/// A revealed password row copies through our concealed, auto-clearing path, never the
/// toolkit's plain `write_to_clipboard`: ⌘C copies the selection (or the whole value) and
/// shows the "Copied — clears in N s" toast, ⌘X with nothing selected does nothing (04 §3),
/// ⌘X copies and deletes a selection and ⌘Z brings it back; a masked row copies nothing.
/// A PIN row takes the same path.
#[gpui::test]
fn revealed_secret_copies_through_the_concealed_path(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let mut item = pw_login("Bank", "s3cret-pw", &state, &vcx);
    item.fields.push(vault_core::Field::new(
        "PIN",
        FieldKind::Pin,
        SecretString::new("4821".into()),
        10,
    ));
    insert_and_select(&state, item, &mut vcx);
    let board = crate::clipboard::fake::FakePasteboard::default();
    state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board.clone())));
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let (key, pin_key) = state.read_with(&vcx, |s, _| {
        let keys = &s.edit_buffer().unwrap().keys;
        (keys[0], keys[1])
    });
    let input = value_input(&main, key, &mut vcx);
    let toolkit = |vcx: &mut VisualTestContext| {
        vcx.update(|_, cx| cx.read_from_clipboard().and_then(|c| c.text()))
    };
    let take_toast = |vcx: &mut VisualTestContext| {
        state.update(vcx, |s, _| s.toast.take().map(|t| t.message.to_string()))
    };
    let buffer_value = |key: u64, vcx: &mut VisualTestContext| {
        state.read_with(vcx, |s, _| {
            let value = &s.edit_buffer().unwrap().field(key).unwrap().value;
            value.expose_secret().to_owned()
        })
    };
    vcx.update(|window, cx| {
        cx.write_to_clipboard(gpui::ClipboardItem::new_string("before".into()));
        ui::focus_input(&input, window, cx);
    });

    // Masked: nothing anywhere.
    vcx.simulate_keystrokes("cmd-a cmd-c");
    vcx.run_until_parked();
    assert_eq!(board.contents(), None);
    assert_eq!(take_toast(&mut vcx), None);

    // Revealed (the eye): selection goes to our pasteboard only, with the toast.
    vcx.update(|window, cx| input.update(cx, |s, cx| s.set_masked(false, window, cx)));
    vcx.simulate_keystrokes("cmd-a cmd-c");
    vcx.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some("s3cret-pw"));
    assert_eq!(toolkit(&mut vcx).as_deref(), Some("before"));
    assert_eq!(
        take_toast(&mut vcx).as_deref(),
        Some("Copied — clears in 30 s")
    );

    // No selection: the whole value.
    board.set("");
    vcx.simulate_keystrokes("right cmd-c");
    vcx.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some("s3cret-pw"));
    assert!(take_toast(&mut vcx).is_some());

    // Cut with no selection: nothing copied anywhere, value intact (04 §3).
    board.set("");
    vcx.simulate_keystrokes("cmd-x");
    vcx.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some(""));
    assert_eq!(toolkit(&mut vcx).as_deref(), Some("before"));
    assert_eq!(take_toast(&mut vcx), None);
    vcx.update(|_, cx| assert_eq!(ui::input_text(&input, cx), "s3cret-pw"));
    assert_eq!(buffer_value(key, &mut vcx), "s3cret-pw");

    // Cut: copied our way, then deleted from the input and the edit buffer.
    vcx.simulate_keystrokes("cmd-a cmd-x");
    vcx.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some("s3cret-pw"));
    assert_eq!(toolkit(&mut vcx).as_deref(), Some("before"));
    assert!(take_toast(&mut vcx).is_some());
    vcx.update(|_, cx| assert_eq!(ui::input_text(&input, cx), ""));
    assert_eq!(buffer_value(key, &mut vcx), "");

    // Undo puts the cut text back in the input and the edit buffer.
    vcx.simulate_keystrokes("cmd-z");
    vcx.run_until_parked();
    vcx.update(|_, cx| assert_eq!(ui::input_text(&input, cx), "s3cret-pw"));
    assert_eq!(buffer_value(key, &mut vcx), "s3cret-pw");

    // A PIN row: masked copies nothing; revealed copies through the same path.
    let pin = value_input(&main, pin_key, &mut vcx);
    board.set("");
    vcx.update(|window, cx| ui::focus_input(&pin, window, cx));
    vcx.simulate_keystrokes("cmd-a cmd-c");
    vcx.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some(""));
    vcx.update(|window, cx| pin.update(cx, |s, cx| s.set_masked(false, window, cx)));
    vcx.simulate_keystrokes("cmd-a cmd-c");
    vcx.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some("4821"));
    assert_eq!(toolkit(&mut vcx).as_deref(), Some("before"));
    assert_eq!(
        take_toast(&mut vcx).as_deref(),
        Some("Copied — clears in 30 s")
    );
}

/// The key-mismatch banner's master password (sync_banners): revealed, it never reaches
/// the pasteboard.
#[gpui::test]
fn key_mismatch_password_refuses_plain_copy(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.sync.key_mismatch = true;
        cx.notify();
    });
    vcx.run_until_parked();
    let input = main.read_with(&vcx, |m, _| m.key_input.clone());
    ui::assert_revealed_copy_refused(&input, &mut vcx);
}

fn pw_login(
    title: &str,
    password: &str,
    state: &Entity<AppState>,
    vcx: &VisualTestContext,
) -> vault_core::Item {
    let device = state.read_with(vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new(title, device, 10);
    item.fields = vec![vault_core::Field::new(
        "password",
        FieldKind::Password,
        SecretString::new(password.into()),
        10,
    )];
    item
}

/// In edit mode the password notices follow the typed value without saving: a strong
/// value drops the weak strip, another saved item's password shows the reused strip,
/// and an empty value shows none (05 §2.3 "Password notices").
#[gpui::test]
fn password_notices_follow_the_typed_value(cx: &mut TestAppContext) {
    const OTHER: &str = "correct-Horse-battery-staple-42";
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let other = pw_login("Other", OTHER, &state, &vcx);
    insert_and_select(&state, other, &mut vcx);
    let item = pw_login("Bank", "123", &state, &vcx);
    let field = item.fields[0].id;
    let id = insert_and_select(&state, item, &mut vcx);
    let weak = leak(format!("issue-strip {field} Weak Password"));
    let reused = leak(format!("issue-strip {field} Reused Password"));
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    assert!(vcx.debug_bounds(weak).is_some(), "weak strip in edit mode");
    assert!(vcx.debug_bounds(reused).is_none());

    let key = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys[0]);
    let input = value_input(&main, key, &mut vcx);
    retype(&input, "an-entirely-Different-passphrase-7", &mut vcx);
    assert!(
        vcx.debug_bounds(weak).is_none(),
        "strong value: no weak strip"
    );
    assert!(vcx.debug_bounds(reused).is_none());

    retype(&input, OTHER, &mut vcx);
    let b = vcx.debug_bounds(reused).expect("reused strip");
    assert!(vcx.debug_bounds(weak).is_none());
    // Under the value input, inside the row.
    let row = vcx.debug_bounds(leak(format!("edit-row {key}"))).unwrap();
    assert!(row.top() < b.top() && b.bottom() <= row.bottom());

    vcx.update(|window, cx| ui::focus_input(&input, window, cx));
    vcx.simulate_keystrokes("cmd-a backspace");
    vcx.run_until_parked();
    assert!(vcx.debug_bounds(weak).is_none(), "empty value: no strips");
    assert!(vcx.debug_bounds(reused).is_none());

    // Nothing was saved: the stored password and the audit are unchanged.
    state.read_with(&vcx, |s, _| {
        assert!(s.is_editing());
        let stored = s.unlocked_vault().unwrap().get(id).unwrap();
        assert_eq!(stored.fields[0].value.expose_secret(), "123");
        assert!(matches!(
            s.listing.issues(id),
            [FieldIssue {
                issue: crate::audit::Issue::Weak { .. },
                ..
            }]
        ));
    });
}

/// The editor's cached score of row `key`: (weak, reused count) of its notices.
fn cached_issues(
    main: &Entity<MainScreen>,
    key: u64,
    vcx: &mut VisualTestContext,
) -> (bool, Option<usize>) {
    main.read_with(vcx, |m, cx| {
        let scored = &m.editor.read(cx).scores.rows[&key];
        let weak = scored.bits < crate::audit::WEAK_BELOW_BITS;
        let reused = scored.issues.iter().find_map(|i| match i {
            crate::audit::Issue::Reused { count } => Some(*count),
            crate::audit::Issue::Weak { .. } => None,
        });
        assert_eq!(
            weak,
            matches!(
                scored.issues.first(),
                Some(crate::audit::Issue::Weak { .. })
            ),
            "weak strip iff the meter scores weak"
        );
        (weak, reused)
    })
}

/// The cached password notices are rescored when the typed value changes (weak and reused
/// → strong and unique → back) and when the saved vault changes under the edit (the other
/// user of the password deleted: reused → unique without typing).
#[gpui::test]
fn cached_notices_follow_value_and_vault_changes(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let other = insert_and_select(&state, pw_login("Other", "123", &state, &vcx), &mut vcx);
    let item = pw_login("Bank", "123", &state, &vcx);
    let field = item.fields[0].id;
    insert_and_select(&state, item, &mut vcx);
    let weak = leak(format!("issue-strip {field} Weak Password"));
    let reused = leak(format!("issue-strip {field} Reused Password"));
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let key = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys[0]);
    assert_eq!(cached_issues(&main, key, &mut vcx), (true, Some(2)));
    assert!(vcx.debug_bounds(weak).is_some() && vcx.debug_bounds(reused).is_some());

    let input = value_input(&main, key, &mut vcx);
    retype(&input, "an-entirely-Different-passphrase-7", &mut vcx);
    assert_eq!(
        cached_issues(&main, key, &mut vcx),
        (false, None),
        "strong, unique"
    );
    assert!(vcx.debug_bounds(weak).is_none() && vcx.debug_bounds(reused).is_none());

    retype(&input, "123", &mut vcx);
    assert_eq!(
        cached_issues(&main, key, &mut vcx),
        (true, Some(2)),
        "weak, reused again"
    );

    // A vault change while editing: the only other user of "123" is deleted.
    state.update(&mut vcx, |s, cx| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.delete(other, 20))
            .unwrap()
            .unwrap();
        s.vault_changed();
        cx.notify();
    });
    vcx.run_until_parked();
    assert_eq!(
        cached_issues(&main, key, &mut vcx),
        (true, None),
        "now unique"
    );
    assert!(vcx.debug_bounds(weak).is_some() && vcx.debug_bounds(reused).is_none());
}

/// 05 §2.3 "Detail header is pinned", edit mode (owner 2026-11-12): with 40 fields, scrolling
/// the field column to the bottom (directly, or by adding a field) leaves the title, the
/// tags row and the rule where they were, at read mode's header position.
#[gpui::test]
fn edit_header_and_tags_stay_pinned_while_fields_scroll(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new("Long", device, 1);
    item.tags = vec!["work".into()];
    item.fields = (0..40)
        .map(|i| {
            let v = SecretString::new("v".into());
            vault_core::Field::new(format!("f{i}"), FieldKind::Text, v, 1)
        })
        .collect();
    insert_and_select(&state, item, &mut vcx);
    let read_header = vcx.debug_bounds("detail-header").expect("read header");
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();

    let column = vcx.debug_bounds("detail-column").expect("detail column");
    let header = vcx.debug_bounds("editor-header").expect("editor header");
    assert_eq!(
        header.origin, read_header.origin,
        "edit header sits where read's did"
    );
    let first = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys[0]);
    let measure = |vcx: &mut VisualTestContext| {
        let title = vcx.debug_bounds("editor-title").expect("title input");
        let tags = vcx.debug_bounds("edit-tags").expect("tags row");
        let row = vcx.debug_bounds(leak(format!("edit-row {first}")));
        (title, tags, row.map(|r| r.top()))
    };
    let (title, tags, row) = measure(&mut vcx);
    assert!(title.top() >= column.top() && title.bottom() < column.top() + px(120.));
    assert!(tags.top() > title.bottom());
    let scroll = vcx.debug_bounds("editor-scroll").expect("scroll column");
    assert!(
        scroll.top() > tags.bottom(),
        "tags row is outside the scroll column"
    );

    // Scroll to the bottom directly.
    vcx.update(|window, cx| {
        main.read(cx).editor.read(cx).scroll.scroll_to_bottom();
        window.refresh();
    });
    vcx.run_until_parked();
    let (title2, tags2, row2) = measure(&mut vcx);
    assert_ne!(row2, row, "the field rows scrolled");
    assert_eq!(title2, title, "title moved");
    assert_eq!(tags2, tags, "tags row moved");

    // Back to the top, then by adding a field (which scrolls to the bottom).
    vcx.update(|window, cx| {
        let editor = main.read(cx).editor.read(cx);
        editor.scroll.set_offset(gpui::point(px(0.), px(0.)));
        window.refresh();
    });
    vcx.run_until_parked();
    assert_eq!(measure(&mut vcx).2, row, "back at the top");
    state.update(&mut vcx, |s, cx| {
        s.edit(cx, |b| b.focus_row = Some(b.add_field(FieldKind::Text)))
    });
    vcx.run_until_parked();
    let (title3, tags3, row3) = measure(&mut vcx);
    assert_ne!(row3, row, "adding a field scrolled the rows");
    assert_eq!(title3, title, "title moved after add");
    assert_eq!(tags3, tags, "tags row moved after add");
}

/// 05 §2.3 `pin` (owner 2026-11-15): in edit mode a PIN row has the masked input with
/// the reveal eye like a password, but no Generate button, no strength meter and no
/// password notices, even when short and reused; "Add field" lists "PIN" right after
/// Password, and a new PIN row is named "PIN".
#[gpui::test]
fn pin_row_has_no_generate_meter_or_notices(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let pin = |item: &mut vault_core::Item| {
        item.fields.push(vault_core::Field::new(
            "CVV",
            FieldKind::Pin,
            SecretString::new("12".into()),
            10,
        ));
    };
    let mut other = pw_login("Other", "123", &state, &vcx);
    pin(&mut other);
    insert_and_select(&state, other, &mut vcx);
    let mut item = pw_login("Bank", "123", &state, &vcx);
    pin(&mut item);
    let pin_field = item.fields[1].id;
    insert_and_select(&state, item, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let (pw_key, pin_key) = state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        (b.keys[0], b.keys[1])
    });

    // The password row keeps both controls; the PIN row has neither.
    assert!(
        vcx.debug_bounds(leak(format!("generate-btn {pw_key}")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds(leak(format!("strength-meter {pw_key}")))
            .is_some()
    );
    assert!(
        vcx.debug_bounds(leak(format!("generate-btn {pin_key}")))
            .is_none()
    );
    assert!(
        vcx.debug_bounds(leak(format!("strength-meter {pin_key}")))
            .is_none()
    );
    for title in ["Weak Password", "Reused Password"] {
        let key = leak(format!("issue-strip {pin_field} {title}"));
        assert!(vcx.debug_bounds(key).is_none(), "{title}");
    }
    let input = value_input(&main, pin_key, &mut vcx);
    vcx.update(|_, cx| assert!(ui::input_is_masked(&input, cx), "PIN is masked"));
    // Any characters, not only digits.
    retype(&input, "AB-12 x", &mut vcx);
    state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        assert_eq!(b.field(pin_key).unwrap().value.expose_secret(), "AB-12 x");
    });
    // The generator refuses a PIN row as its target.
    state.update(&mut vcx, |s, cx| {
        s.open_generator(GeneratorTarget::Field(pin_key), cx)
    });
    assert!(state.read_with(&vcx, |s, _| s.generator_target.is_none()));

    // "Add field": PIN directly under Password, labelled "PIN"; the new row is "PIN".
    click(&mut vcx, "add-field".into());
    let top = |vcx: &mut VisualTestContext, k: &str| {
        vcx.debug_bounds(leak(format!("add-field-{k}")))
            .expect(k)
            .top()
    };
    let (pw, pn, totp) = (
        top(&mut vcx, "password"),
        top(&mut vcx, "pin"),
        top(&mut vcx, "totp"),
    );
    assert!(pw < pn && pn < totp, "{pw:?} {pn:?} {totp:?}");
    click(&mut vcx, "add-field-pin".into());
    state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        let f = b.item.fields.last().unwrap();
        assert_eq!((f.kind, f.name.as_str()), (FieldKind::Pin, "PIN"));
    });
}

/// 05 §2.3 `pin` history (2026-11-15): editing a PIN and a password in one save records
/// one entry each; read mode shows the PIN's under the PIN row (own toggle, field name,
/// copy) and the password's under the password row. ⌘⇧R reveals the password, never the
/// PIN.
#[gpui::test]
fn pin_and_password_edits_keep_separate_history_rows(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let mut item = pw_login("Card", "pw-old", &state, &vcx);
    item.fields.push(vault_core::Field::new(
        "CVV",
        FieldKind::Pin,
        SecretString::new("111".into()),
        10,
    ));
    let (pw_id, pin_id) = (item.fields[0].id, item.fields[1].id);
    let id = insert_and_select(&state, item, &mut vcx);
    let board = crate::clipboard::fake::FakePasteboard::default();
    state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board.clone())));

    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    retype(&value_input(&main, keys[0], &mut vcx), "pw-new", &mut vcx);
    retype(&value_input(&main, keys[1], &mut vcx), "222", &mut vcx);
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();

    state.update(&mut vcx, |s, cx| {
        let item = s.unlocked_vault().unwrap().get(id).unwrap();
        let old = |field| {
            let h = item.history.iter().find(|h| h.field_id == Some(field));
            h.map(|h| (h.value.expose_secret().to_owned(), h.replaced_at))
        };
        let pin_modified = item.field_by_id(pin_id).unwrap().modified_at;
        assert_eq!(old(pin_id), Some(("111".to_owned(), pin_modified)));
        assert_eq!(old(pw_id).map(|o| o.0).as_deref(), Some("pw-old"));
        assert_eq!(item.history.len(), 2);
        s.toggle_history(cx);
    });
    vcx.run_until_parked();

    // One disclosure per row, each directly under its own row.
    let at = |vcx: &mut VisualTestContext, k: &str| vcx.debug_bounds(leak(k.into())).expect(k);
    let (pw_row, pin_row) = (at(&mut vcx, "field-value 0"), at(&mut vcx, "field-value 1"));
    let pw_toggle = at(&mut vcx, "history-toggle");
    let pin_toggle = at(&mut vcx, "history-toggle pin1");
    assert!(pw_row.bottom() <= pw_toggle.top() && pw_toggle.bottom() <= pin_row.top());
    assert!(pin_row.bottom() <= pin_toggle.top());
    at(&mut vcx, "history-label Password history (1)");
    at(&mut vcx, "history-label PIN history (1)");
    at(&mut vcx, "history-entry 0 Password");
    at(&mut vcx, "history-entry 0 CVV pin1");
    assert!(
        vcx.debug_bounds("history-entry 1 Password").is_none(),
        "one each"
    );
    assert!(vcx.debug_bounds("history-entry 1 CVV pin1").is_none());

    // Both entries carry the same stamp today (one save); copy is keyed by stamp and
    // field id, so this still holds once core gives each entry a unique stamp.
    click(&mut vcx, "history-copy 0 pin1".into());
    assert_eq!(board.contents().as_deref(), Some("111"));
    click(&mut vcx, "history-copy 0".into());
    assert_eq!(board.contents().as_deref(), Some("pw-old"));

    vcx.simulate_keystrokes("cmd-shift-r");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert!(s.revealed.contains(&pw_id));
        assert!(!s.revealed.contains(&pin_id), "⌘⇧R is password-only");
    });
}

/// "Clear history" under a PIN's disclosure marks only that PIN's entries: the password's
/// history is untouched and each disclosure counts its own pending removals. Stamps differ
/// per field here (separate saves) so the per-stamp removal cannot cross fields.
#[gpui::test]
fn clearing_pin_history_leaves_the_password_history(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    let mut item = pw_login("Card", "pw-a", &state, &vcx);
    item.fields.push(vault_core::Field::new(
        "CVV",
        FieldKind::Pin,
        SecretString::new("111".into()),
        10,
    ));
    let (pw_id, pin_id) = (item.fields[0].id, item.fields[1].id);
    let id = insert_and_select(&state, item, &mut vcx);
    state.update(&mut vcx, |s, cx| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| {
                v.set_field(id, pw_id, SecretString::new("pw-b".into()), 20)?;
                v.set_field(id, pin_id, SecretString::new("222".into()), 30)?;
                v.set_field(id, pin_id, SecretString::new("333".into()), 40)
            })
            .unwrap()
            .unwrap();
        s.vault_changed();
        s.select(id, cx);
        s.toggle_history(cx);
        s.begin_edit(cx);
    });
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("history-remove 1 pin1").is_some());
    click(&mut vcx, "history-clear pin1".into());

    state.read_with(&vcx, |s, _| {
        let b = s.edit_buffer().unwrap();
        let left: Vec<_> = b.history().map(|h| h.field_id).collect();
        assert_eq!(left, [Some(pw_id)], "only the password's entry remains");
        assert_eq!(b.removed_history.len(), 2);
    });
    assert!(
        vcx.debug_bounds("history-removed 2 pin1").is_some(),
        "PIN count"
    );
    assert!(
        vcx.debug_bounds("history-toggle pin1").is_some(),
        "PIN toggle kept"
    );
    assert!(vcx.debug_bounds("history-removed 2").is_none());
    assert!(
        vcx.debug_bounds("history-remove 0").is_some(),
        "password entry kept"
    );
    assert!(vcx.debug_bounds("history-clear").is_some());

    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        let item = s.unlocked_vault().unwrap().get(id).unwrap();
        let ids: Vec<_> = item.history.iter().map(|h| h.field_id).collect();
        assert_eq!(ids, [Some(pw_id)]);
    });
}

fn search_query(state: &Entity<AppState>, vcx: &VisualTestContext) -> String {
    state.read_with(vcx, |s, _| s.icon_search.query().to_owned())
}

fn search_hit(state: &Entity<AppState>, vcx: &VisualTestContext) -> Option<usize> {
    state.read_with(vcx, |s, _| s.icon_search.hit())
}

/// 05 "Icon search" (Lucide catalog): the field is focused on open; typing searches the
/// catalog once per query change; Space types; a catalog icon is stored as kind
/// `symbol` and takes the swatches; the list row shows it; no-match text.
#[gpui::test]
fn icon_search_picks_a_catalog_icon(cx: &mut TestAppContext) {
    use crate::icon::PALETTE;
    let (_dir, state, mut vcx, default) = picker_on("Notes", Some("https://github.com"), cx);
    // Empty query: the 40 curated symbols as before.
    assert!(vcx.debug_bounds("icon-search").is_some());
    assert!(vcx.debug_bounds("icon-symbol 39").is_some());
    let grid = vcx.debug_bounds("icon-grid").unwrap().size;

    vcx.simulate_keystrokes("c l o c k");
    vcx.run_until_parked();
    assert_eq!(search_query(&state, &vcx), "clock");
    assert!(vcx.debug_bounds("icon-symbol 39").is_none());
    assert!(vcx.debug_bounds("icon-hit 0 Clock").is_some());
    assert!(vcx.debug_bounds("icon-hit 1 Clock1").is_some());
    assert_eq!(
        vcx.debug_bounds("icon-grid").unwrap().size,
        grid,
        "fixed size"
    );

    // Results are computed once per query change: redraws and arrows do not search.
    crate::icon::SEARCH_CALLS.with(|c| c.set(0));
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
    vcx.simulate_keystrokes("down up");
    vcx.run_until_parked();
    assert_eq!(crate::icon::SEARCH_CALLS.with(|c| c.get()), 0);

    // Space types in the field; with a query ←/→ move the caret, not the cursor.
    vcx.simulate_keystrokes("cmd-a a l a r m space c");
    vcx.run_until_parked();
    assert_eq!(search_query(&state, &vcx), "alarm c");
    vcx.simulate_keystrokes("left x");
    vcx.run_until_parked();
    assert_eq!(search_query(&state, &vcx), "alarm xc");
    assert_eq!(search_hit(&state, &vcx), None, "no cursor move");

    // ↓ enters the results, → moves, Enter picks: stored as kind symbol.
    vcx.simulate_keystrokes("cmd-a c l o c k down right enter");
    vcx.run_until_parked();
    let icon = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().item.icon.clone());
    let icon = icon.expect("icon chosen");
    assert_eq!(
        (icon.kind.as_str(), icon.value.as_str(), icon.color),
        ("symbol", "Clock1", None)
    );
    assert!(vcx.debug_bounds("icon-hit-chosen 1 Clock1").is_some());
    assert!(vcx.debug_bounds("icon-auto-selected").is_none());

    // Swatches apply to catalog icons; the header tile follows.
    let x_ix = PALETTE.iter().position(|c| *c != default).unwrap();
    click(&mut vcx, format!("icon-color {x_ix}"));
    let tile = leak(format!(
        "icon-tile symbol Clock1 #{:06X} fill white",
        PALETTE[x_ix]
    ));
    assert!(vcx.debug_bounds(tile).is_some(), "{tile}");
    // Dark appearance: the same filled tile with a white glyph (no contrast fallbacks).
    for mode in [
        gpui_component::ThemeMode::Dark,
        gpui_component::ThemeMode::Light,
    ] {
        vcx.update(|window, cx| gpui_component::Theme::change(mode, Some(window), cx));
        vcx.run_until_parked();
        assert!(vcx.debug_bounds(tile).is_some(), "{mode:?}");
    }

    // No match (the swatch click took the focus; a click puts it back in the field).
    click(&mut vcx, "icon-search".into());
    vcx.simulate_keystrokes("cmd-a z z q q x");
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("icon-no-match").is_some());

    // Save: the list row shows it.
    vcx.simulate_keystrokes("escape");
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("icon-picker").is_none());
    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let notes = state.read_with(&vcx, |s, _| s.selection).unwrap();
    // Another item in the detail column, so the only Clock1 tile is the list row's.
    insert_and_select(&state, vault_core::Item::new("Zeta", device, 10), &mut vcx);
    let shown = vcx.debug_bounds(tile).expect("list tile");
    assert!(
        (0..4).any(|ix| vcx
            .debug_bounds(leak(format!("item-row {ix}")))
            .is_some_and(|row| row.contains(&shown.center()))),
        "list row shows the catalog icon"
    );

    // Reopened: the query is gone; Automatic gives the (tinted) letter again.
    state.update(&mut vcx, |s, cx| s.select(notes, cx));
    vcx.run_until_parked();
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    click(&mut vcx, "edit-icon".into());
    assert_eq!(search_query(&state, &vcx), "");
    assert!(vcx.debug_bounds("icon-symbol 39").is_some());
    click(&mut vcx, "icon-picker-automatic".into());
    state.read_with(&vcx, |s, _| {
        let icon = s.edit_buffer().unwrap().item.icon.clone().unwrap();
        assert_eq!(icon.kind, "letter", "the colour stays");
    });
}

/// The keyboard cursor stays visible: moving it past the visible rows scrolls the grid,
/// and a query change scrolls back to the top.
#[gpui::test]
fn icon_search_grid_scrolls_to_the_cursor(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let device = state.read_with(&vcx, |s, _| s.device_id());
    insert_and_select(&state, vault_core::Item::new("Notes", device, 10), &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    click(&mut vcx, "edit-icon".into());
    let scroll = vcx.update(|_, cx| main.read(cx).editor.read(cx).icon_scroll.clone());
    vcx.simulate_keystrokes("a");
    vcx.run_until_parked();
    let rows = crate::icon::SEARCH_CAP.div_ceil(crate::icon::GRID_COLS);
    assert!(rows > 6, "{rows} rows, more than the 5 that fit");
    assert_eq!(scroll.offset().y, px(0.));
    // ↓ enters the results on row 0; six more reach row 6, below the fold.
    vcx.simulate_keystrokes("down down down down down down down");
    vcx.run_until_parked();
    assert_eq!(search_hit(&state, &vcx), Some(6 * crate::icon::GRID_COLS));
    assert!(scroll.offset().y < px(0.), "scrolled");
    // Child bounds are unscrolled layout bounds: shift them by the offset.
    let (view, row) = (scroll.bounds(), scroll.bounds_for_item(6).unwrap());
    let dy = scroll.offset().y;
    assert!(
        row.top() + dy >= view.top() && row.bottom() + dy <= view.bottom(),
        "cursor row {row:?} inside {view:?}"
    );
    vcx.simulate_keystrokes("up up up up up up");
    vcx.run_until_parked();
    assert_eq!(scroll.offset().y, px(0.));
    // Scrolled down again, then the query changes: new results start at the top.
    vcx.simulate_keystrokes("down down down down down down");
    vcx.run_until_parked();
    assert!(scroll.offset().y < px(0.));
    vcx.simulate_keystrokes("r");
    vcx.run_until_parked();
    assert_eq!(search_query(&state, &vcx), "ar");
    assert_eq!(scroll.offset().y, px(0.));
    assert_eq!(search_hit(&state, &vcx), None);
}

/// 05 "Field icons" + "Icon search": the field picker has the same search; a catalog
/// icon is stored on the field and drawn in the read-mode row. After a cell click the
/// picker still works by keyboard (arrows, Esc).
#[gpui::test]
fn field_icon_search_picks_a_catalog_icon(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let (id, [user, _, password]) = editing_with_section(&state, &mut vcx);
    click(&mut vcx, format!("field-icon-button {user} none"));
    assert!(vcx.debug_bounds("icon-search").is_some(), "search field");
    assert!(vcx.debug_bounds("field-icon-symbol 39").is_some());
    vcx.simulate_keystrokes("a l a r m space c l o c k");
    vcx.run_until_parked();
    assert_eq!(search_query(&state, &vcx), "alarm clock");
    assert!(vcx.debug_bounds("field-icon-symbol 39").is_none());
    click(&mut vcx, "field-icon-hit 0 AlarmClock".into());
    assert_eq!(
        field_icon(&state, user, &vcx).as_deref(),
        Some("AlarmClock")
    );
    assert!(
        state.read_with(&vcx, |s, _| s.field_icon_picker().is_none()),
        "a pick closes"
    );
    assert!(name_focused(&main, user, &mut vcx));
    assert!(
        vcx.debug_bounds(leak(format!("field-icon-button {user} AlarmClock")))
            .is_some()
    );

    // Reopened: empty query; arrows and Esc still work.
    click(&mut vcx, format!("field-icon-button {password} none"));
    assert_eq!(search_query(&state, &vcx), "");
    vcx.simulate_keystrokes("down right");
    vcx.run_until_parked();
    let cursor = state.read_with(&vcx, |s, _| s.field_icon_picker().map(|(_, c)| c.cell()));
    assert_eq!(cursor, Some(crate::icon::PickerCell::Symbol(1)));
    vcx.simulate_keystrokes("escape");
    vcx.run_until_parked();
    assert!(
        state.read_with(&vcx, |s, _| s.field_icon_picker().is_none()),
        "Esc closes"
    );
    assert!(name_focused(&main, password, &mut vcx));

    vcx.simulate_keystrokes("cmd-s");
    vcx.run_until_parked();
    let item = state.read_with(&vcx, |s, _| {
        s.unlocked_vault().unwrap().get(id).unwrap().clone()
    });
    assert_eq!(item.fields[0].icon.as_deref(), Some("AlarmClock"));
    assert!(
        vcx.debug_bounds("field-row-icon 0 AlarmClock").is_some(),
        "read mode draws it from the catalog"
    );
}
