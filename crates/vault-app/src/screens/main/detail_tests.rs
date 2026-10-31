//! Headless render tests for detail layout, copying and password warnings.

use std::sync::Arc;

use gpui::{AppContext as _, TestAppContext, VisualTestContext};
use gpui_component::Root;
use vault_core::{KdfParams, SecretString, Uuid};
use vault_sync::{NoopHooks, SyncedVault};

use super::super::MainScreen;
use super::*;
use crate::actions;
use crate::clipboard::fake::FakePasteboard;

const STRONG: &str = "correct-Horse-battery-staple-42";
const TOTP_URI: &str = "otpauth://totp/GitHub:chris?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

fn login(title: &str, password: &str, device: Uuid) -> Item {
    let mut item = Item::new(title, device, 1);
    item.fields.push(Field::new(
        "username",
        FieldKind::Text,
        SecretString::new("chris".into()),
        1,
    ));
    item.fields.push(Field::new(
        "password",
        FieldKind::Password,
        SecretString::new(password.into()),
        1,
    ));
    item
}

/// The main screen over a vault holding one login per `(title, password)`.
fn open(
    dir: &std::path::Path,
    logins: &[(&str, &str)],
    cx: &mut TestAppContext,
) -> (Entity<AppState>, Vec<Uuid>, VisualTestContext) {
    let logins = logins.to_vec();
    open_items(
        dir,
        move |device| logins.iter().map(|(t, pw)| login(t, pw, device)).collect(),
        cx,
    )
}

/// The main screen over a vault holding the items `make(device_id)` builds.
fn open_items(
    dir: &std::path::Path,
    make: impl FnOnce(Uuid) -> Vec<Item>,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, Vec<Uuid>, VisualTestContext) {
    let mut vault = SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new("pw".into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let ids = vault
        .edit(|v| {
            make(v.device_id())
                .into_iter()
                .map(|item| v.insert(item, 1))
                .collect::<Vec<_>>()
        })
        .unwrap();
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    cx.update(|cx| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        actions::register(&state, cx);
    });
    state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
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
    (state, ids, vcx)
}

fn select(state: &Entity<AppState>, id: Uuid, vcx: &mut VisualTestContext) {
    vcx.update(|_, cx| state.update(cx, |s, cx| s.select(id, cx)));
    vcx.run_until_parked();
}

fn shown(key: &'static str, vcx: &mut VisualTestContext) -> bool {
    vcx.debug_bounds(key).is_some()
}

/// Edits the selected item's password field to `password` and saves.
fn change_password(state: &Entity<AppState>, password: &str, vcx: &mut VisualTestContext) {
    vcx.update(|_, cx| {
        state.update(cx, |s, cx| {
            s.begin_edit(cx);
            let b = s.edit_buffer().unwrap();
            let ix = b
                .item
                .fields
                .iter()
                .position(|f| f.kind == FieldKind::Password)
                .unwrap();
            let key = b.keys[ix];
            s.set_edit_value(key, SecretString::new(password.into()), cx);
            s.save_edit(cx);
            assert!(!s.is_editing());
        });
    });
    vcx.run_until_parked();
}

#[gpui::test]
fn weak_password_shows_badge_and_banner_until_fixed(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("Bank", "123")], cx);
    select(&state, ids[0], &mut vcx);
    assert!(shown("issue-badge Weak password", &mut vcx));
    assert!(shown("issue-banner Weak Password", &mut vcx));
    assert!(!shown("issue-banner Reused Password", &mut vcx));

    change_password(&state, STRONG, &mut vcx);
    assert!(!shown("issue-badge Weak password", &mut vcx));
    assert!(!shown("issue-banner Weak Password", &mut vcx));
}

#[gpui::test]
fn reused_password_flags_both_items(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", STRONG), ("Beta", STRONG)], cx);
    select(&state, ids[0], &mut vcx);
    // One badge per row, both rows flagged.
    assert!(shown("issue-badge Reused password", &mut vcx));
    let rows = state.read_with(&vcx, |s, _| s.listing.issues.len());
    assert_eq!(rows, 2);
    assert!(shown("issue-banner Reused Password", &mut vcx));
    assert!(!shown("issue-banner Weak Password", &mut vcx));

    change_password(&state, "an-entirely-Different-passphrase-7", &mut vcx);
    assert!(!shown("issue-badge Reused password", &mut vcx));
    assert!(!shown("issue-banner Reused Password", &mut vcx));
}

#[gpui::test]
fn search_reuses_the_audit_and_edits_redo_it(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", "123"), ("Beta", STRONG)], cx);
    let before = state.read_with(&vcx, |s, _| s.listing.issues.clone());
    vcx.update(|_, cx| state.update(cx, |s, cx| s.set_query("Al".into(), cx)));
    let after = state.read_with(&vcx, |s, _| s.listing.issues.clone());
    assert!(std::rc::Rc::ptr_eq(&before, &after), "search re-audited");
    assert_eq!(after.len(), 1);

    vcx.update(|_, cx| state.update(cx, |s, cx| s.set_query(String::new(), cx)));
    select(&state, ids[0], &mut vcx);
    change_password(&state, STRONG, &mut vcx);
    let edited = state.read_with(&vcx, |s, _| s.listing.issues.clone());
    assert!(!std::rc::Rc::ptr_eq(&before, &edited));
    // Alpha now shares Beta's password.
    assert!(
        edited
            .values()
            .all(|v| matches!(v.as_slice(), [Issue::Reused { count: 2 }]))
    );
}

/// Opens one login (username, password, totp) with a fake pasteboard installed.
fn open_with_board(
    dir: &std::path::Path,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, FakePasteboard, VisualTestContext) {
    let (state, ids, mut vcx) = open_items(
        dir,
        |device| {
            let mut item = login("GitHub", STRONG, device);
            item.fields.push(Field::new(
                "totp",
                FieldKind::Totp,
                SecretString::new(TOTP_URI.into()),
                1,
            ));
            vec![item]
        },
        cx,
    );
    let board = FakePasteboard::default();
    vcx.update(|_, cx| {
        state.update(cx, |s, _| {
            s.set_pasteboard(Box::new(board.clone()));
            s.settings.clipboard_clear_secs = 30;
        });
    });
    select(&state, ids[0], &mut vcx);
    (state, board, vcx)
}

fn click(key: &'static str, vcx: &mut VisualTestContext) {
    let at = vcx.debug_bounds(key).expect(key).center();
    vcx.simulate_click(at, gpui::Modifiers::none());
    vcx.run_until_parked();
}

#[gpui::test]
fn clicking_the_password_copies_it_and_keeps_it_masked(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, board, mut vcx) = open_with_board(dir.path(), cx);
    click("field-value 1", &mut vcx);
    assert_eq!(board.contents().as_deref(), Some(STRONG));
    state.read_with(&vcx, |s, _| {
        let toast = s.toast.as_ref().expect("copied pill");
        assert_eq!(toast.message.as_ref(), "Copied — clears in 30 s");
        assert_eq!(toast.place, ToastPlace::Detail);
        assert!(s.revealed.is_empty(), "the click revealed the password");
    });
    // Same auto-clear as the Copy button.
    vcx.executor().advance_clock(Duration::from_secs(31));
    vcx.run_until_parked();
    assert_eq!(board.contents(), None);
}

#[gpui::test]
fn clicking_the_totp_copies_the_current_code(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_state, board, mut vcx) = open_with_board(dir.path(), cx);
    let totp = parse_totp(&SecretString::new(TOTP_URI.into())).unwrap();
    let before = totp.code(text::now_millis() / 1000);
    click("field-value 2", &mut vcx);
    let after = totp.code(text::now_millis() / 1000);
    let copied = board.contents().expect("copied");
    assert_eq!(copied.len(), 6);
    assert!(copied.bytes().all(|b| b.is_ascii_digit()));
    assert!(copied == before || copied == after, "not the current code");
}

#[gpui::test]
fn enter_on_a_focused_value_copies(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_state, board, mut vcx) = open_with_board(dir.path(), cx);
    click("field-value 0", &mut vcx);
    assert_eq!(board.contents().as_deref(), Some("chris"));
    board.set("elsewhere");
    // The click focused the value area; Enter clicks it again (on key up).
    vcx.simulate_keystrokes("enter");
    vcx.simulate_event(gpui::KeyUpEvent {
        keystroke: gpui::Keystroke::parse("enter").unwrap(),
    });
    vcx.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some("chris"));
}

#[gpui::test]
fn clicking_in_edit_mode_copies_nothing(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, board, mut vcx) = open_with_board(dir.path(), cx);
    let at = vcx.debug_bounds("field-value 1").unwrap().center();
    vcx.update(|_, cx| state.update(cx, |s, cx| s.begin_edit(cx)));
    vcx.run_until_parked();
    assert!(
        !shown("field-value 1", &mut vcx),
        "editor shows click-to-copy"
    );
    vcx.simulate_click(at, gpui::Modifiers::none());
    vcx.run_until_parked();
    assert_eq!(board.contents(), None);
    state.read_with(&vcx, |s, _| assert!(s.toast.is_none()));
}

#[gpui::test]
fn field_labels_and_values_share_aligned_rows_at_different_widths(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open_items(
        dir.path(),
        |device| {
            let mut item = login("Alpha", STRONG, device);
            item.fields.push(Field::new(
                "notes",
                FieldKind::Notes,
                SecretString::new("First line\nSecond line\nThird line".into()),
                1,
            ));
            item.fields.push(Field::new(
                "A custom field with a longer label",
                FieldKind::Text,
                SecretString::new("Value".into()),
                1,
            ));
            vec![item]
        },
        cx,
    );
    select(&state, ids[0], &mut vcx);
    for width in [820., 1100., 1400.] {
        vcx.simulate_resize(gpui::size(px(width), px(900.)));
        vcx.run_until_parked();
        let first = vcx.debug_bounds("field-content 0").unwrap();
        for (row, label, content) in [
            ("field-row 0", "field-label 0", "field-content 0"),
            ("field-row 1", "field-label 1", "field-content 1"),
            ("field-row 2", "field-label 2", "field-content 2"),
            ("field-row 3", "field-label 3", "field-content 3"),
        ] {
            let row = vcx.debug_bounds(row).unwrap();
            let label = vcx.debug_bounds(label).unwrap();
            let content = vcx.debug_bounds(content).unwrap();
            assert_eq!(content.left(), first.left(), "aligned value column");
            assert!(label.right() < content.left(), "label beside its value");
            assert_eq!(label.top(), content.top(), "same row baseline padding");
            assert!(content.size.width > px(0.));
            assert!(content.right() <= row.right(), "content fits its row");
        }
        let single = vcx.debug_bounds("field-row 0").unwrap();
        let notes = vcx.debug_bounds("field-row 2").unwrap();
        assert!(
            notes.size.height > single.size.height,
            "notes retain line breaks"
        );
    }
}

#[gpui::test]
fn one_rule_between_last_field_and_footer(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", STRONG)], cx);
    select(&state, ids[0], &mut vcx);
    let last = vcx.debug_bounds("field-row 1").expect("last field row");
    let footer = vcx.debug_bounds("detail-footer").expect("footer");
    // The last row's own bottom border is the only rule: the footer follows after
    // exactly one column gap, with no extra divider (1 px + another gap) between.
    assert_eq!(footer.top() - last.bottom(), px(12.));
}

#[gpui::test]
fn field_rows_use_7px_padding_and_label_foreground_value_muted(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", STRONG)], cx);
    select(&state, ids[0], &mut vcx);
    for ix in 0..2 {
        let row = vcx
            .debug_bounds(Box::leak(format!("field-row {ix}").into_boxed_str()))
            .unwrap();
        let content = vcx
            .debug_bounds(Box::leak(format!("field-content {ix}").into_boxed_str()))
            .unwrap();
        assert_eq!(
            content.top() - row.top(),
            px(FIELD_ROW_PAD_Y),
            "top padding"
        );
        // Bottom: padding plus the 1 px rule.
        assert_eq!(
            row.bottom() - content.bottom(),
            px(FIELD_ROW_PAD_Y + 1.),
            "bottom padding"
        );
    }
    assert_eq!(FIELD_ROW_PAD_Y, 7., "12 px before, about 5 px less");
    // Label in the foreground colour, value in the muted foreground, both appearances.
    for mode in [
        gpui_component::ThemeMode::Light,
        gpui_component::ThemeMode::Dark,
    ] {
        vcx.update(|window, cx| {
            gpui_component::Theme::change(mode, Some(window), cx);
            let theme = cx.theme();
            assert_eq!(
                field_row_colors(cx),
                (theme.foreground, theme.muted_foreground)
            );
            assert_ne!(theme.foreground, theme.muted_foreground);
        });
    }
}

/// Draws a frame and returns the detail content probe's records from it.
fn content_probe(vcx: &mut VisualTestContext) -> crate::ui::probe::Seen {
    crate::ui::probe::take();
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
    crate::ui::probe::take()
        .into_iter()
        .rev()
        .find(|s| s.name == "detail-content-probe")
        .expect("detail content rendered")
}

/// Edit and Cancel keep the detail content (inside the fade-in) at the same element
/// path with its state, so the fade does not replay (the edit blink). Selecting
/// another item still restarts it.
#[gpui::test]
fn edit_and_cancel_do_not_replay_the_detail_fade(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("GitHub", "a"), ("Mail", "b")], cx);
    select(&state, ids[0], &mut vcx);
    let read = content_probe(&mut vcx);
    assert!(read.path.contains("detail-in"), "{}", read.path);

    vcx.update(|_, cx| state.update(cx, |s, cx| s.begin_edit(cx)));
    vcx.run_until_parked();
    assert!(state.read_with(&vcx, |s, _| s.is_editing()));
    let editing = content_probe(&mut vcx);
    assert_eq!(editing.path, read.path, "Edit changed the faded container");
    assert!(!editing.fresh, "Edit restarted the fade");

    vcx.update(|_, cx| state.update(cx, |s, cx| s.cancel_edit(cx)));
    vcx.run_until_parked();
    assert!(!state.read_with(&vcx, |s, _| s.is_editing()));
    let cancelled = content_probe(&mut vcx);
    assert_eq!(
        cancelled.path, read.path,
        "Cancel changed the faded container"
    );
    assert!(!cancelled.fresh, "Cancel restarted the fade");

    // A different item does fade in: its first frame has a fresh fade state.
    crate::ui::probe::take();
    select(&state, ids[1], &mut vcx);
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
    let other = crate::ui::probe::take()
        .into_iter()
        .find(|s| s.name == "detail-content-probe")
        .expect("detail content rendered");
    assert_ne!(other.path, read.path);
    assert!(other.fresh, "a new selection restarts the fade");
}

/// The rule under the tags sits as far above the first row's content as each row's
/// bottom border sits above the next row's content: the row's own top padding only.
/// Same in the item window, which uses the same renderer.
#[gpui::test]
fn first_field_row_sits_under_the_rule_like_the_others(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("GitHub", "a")], cx);
    select(&state, ids[0], &mut vcx);
    let spacing = |vcx: &mut VisualTestContext| {
        let b = |key: &'static str, vcx: &mut VisualTestContext| {
            vcx.debug_bounds(key)
                .unwrap_or_else(|| panic!("{key} not rendered"))
        };
        let rule = b("detail-fields-rule", vcx);
        let row0 = b("field-row 0", vcx);
        let first = b("field-content 0", vcx).top() - rule.bottom();
        let between = b("field-content 1", vcx).top() - row0.bottom();
        (first, between)
    };
    let (first, between) = spacing(&mut vcx);
    assert_eq!(first, between, "main window");
    assert_eq!(first, gpui::px(FIELD_ROW_PAD_Y));

    let main_window = vcx.cx.update(|cx| cx.windows()[0]);
    vcx.update(|_, cx| {
        crate::screens::open_item_window(state.clone(), ids[0], cx).unwrap();
    });
    vcx.run_until_parked();
    let item_window = vcx
        .cx
        .update(|cx| cx.windows())
        .into_iter()
        .find(|w| w.window_id() != main_window.window_id())
        .expect("item window");
    let mut item = VisualTestContext::from_window(item_window, &vcx.cx);
    item.run_until_parked();
    let (first, between) = spacing(&mut item);
    assert_eq!(first, between, "item window");
    assert_eq!(first, gpui::px(FIELD_ROW_PAD_Y));
}

#[gpui::test]
fn labels_show_a_capital_but_stored_names_stay(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids, mut vcx) = open(dir.path(), &[("Alpha", STRONG)], cx);
    select(&state, ids[0], &mut vcx);
    let names: Vec<String> = state.read_with(&vcx, |s, _| {
        s.selected_item()
            .unwrap()
            .fields
            .iter()
            .map(|f| f.name.clone())
            .collect()
    });
    assert_eq!(names[0], "username", "the fixture stores lowercase names");
    assert!(vcx.debug_bounds("field-label-text 0 Username").is_some());
    assert!(vcx.debug_bounds("field-label-text 0 username").is_none());
    // Display only: the item and the editor keep the stored spelling.
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| {
        assert_eq!(s.edit_buffer().unwrap().item.fields[0].name, "username");
    });
}
