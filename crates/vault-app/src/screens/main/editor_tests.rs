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
            ValueInput::Area(_) => panic!("not a line input"),
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
                v.set_field(id, "password", SecretString::new("b".into()), 20)?;
                v.set_field(id, "password", SecretString::new("c".into()), 30)?;
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
    // Automatic: the GitHub logo, in the list row and the detail header (light appearance).
    assert!(
        vcx.debug_bounds("icon-tile logo github fill white")
            .is_some(),
        "automatic logo"
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
fn insert_and_select(
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

    // Damage the blob and lock/unlock: the decode fails, the automatic logo shows.
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
    assert!(
        vcx.debug_bounds("icon-tile logo github fill white")
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
fn name_input(
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

fn leak(s: String) -> &'static str {
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
fn logo_disables_the_colour_row(cx: &mut TestAppContext) {
    use crate::icon::PALETTE;
    let (_dir, state, mut vcx, default) = picker_on("Code", Some("https://github.com"), cx);
    assert!(
        vcx.debug_bounds("icon-color-disabled").is_some(),
        "hint shown"
    );
    assert!(
        vcx.debug_bounds("icon-auto-preview logo github").is_some(),
        "Automatic previews the logo"
    );
    assert!(vcx.debug_bounds("icon-auto-selected").is_some());
    let x_ix = PALETTE.iter().position(|c| *c != default).unwrap();
    click(&mut vcx, format!("icon-color {x_ix}"));
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.edit_buffer().unwrap().item.icon, None, "click ignored");
    });
    // With a symbol the colour row works again.
    click(&mut vcx, "icon-symbol 0".into());
    assert!(vcx.debug_bounds("icon-color-disabled").is_none());
    click(&mut vcx, format!("icon-color {x_ix}"));
    state.read_with(&vcx, |s, _| {
        let i = s.edit_buffer().unwrap().item.icon.clone().unwrap();
        assert_eq!(i.color, Some(crate::icon::format_color(PALETTE[x_ix])));
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
