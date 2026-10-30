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
