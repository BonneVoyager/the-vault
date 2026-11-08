//! The item list is one Tab stop between the search field and the detail column
//! (05 §6, owner decision 2026-11-08); rows never are.

use gpui::{Entity, TestAppContext, VisualTestContext};

use super::MainScreen;
use super::tests::open;

/// The main screen with the search field focused by ⌘F, in an active window (focus
/// listeners stay silent in an inactive one).
fn from_search(
    populated: bool,
    cx: &mut TestAppContext,
) -> (Entity<MainScreen>, VisualTestContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(populated, dir.path(), cx);
    // Nothing selected, as after deleting an item that was not in the list.
    state.update(&mut vcx, |s, _| s.selection = None);
    vcx.update(|w, _| w.activate_window());
    vcx.simulate_keystrokes("cmd-f");
    vcx.run_until_parked();
    assert!(vcx.update(|w, cx| main.read(cx).search_focused(w, cx)));
    (main, vcx)
}

fn tab(keys: &str, vcx: &mut VisualTestContext) {
    vcx.simulate_keystrokes(keys);
    // Draw the frame the next Tab reads its order from.
    vcx.update(|w, _| w.refresh());
    vcx.run_until_parked();
}

fn list_focused(main: &Entity<MainScreen>, vcx: &mut VisualTestContext) -> bool {
    vcx.update(|w, cx| main.read(cx).list_focus.is_focused(w))
}

#[gpui::test]
fn tab_from_search_focuses_the_list_and_selects_the_first_row(cx: &mut TestAppContext) {
    let (main, mut vcx) = from_search(true, cx);
    tab("tab", &mut vcx);
    assert!(list_focused(&main, &mut vcx), "Tab lands on the list");
    let (selection, first) = vcx.update(|_, cx| {
        let s = main.read(cx).state.read(cx);
        (s.selection, s.listing.items.first().copied())
    });
    assert!(first.is_some());
    assert_eq!(selection, first, "the first row is selected");
}

#[gpui::test]
fn shift_tab_from_the_list_returns_to_search(cx: &mut TestAppContext) {
    let (main, mut vcx) = from_search(true, cx);
    tab("tab", &mut vcx);
    tab("shift-tab", &mut vcx);
    assert!(vcx.update(|w, cx| main.read(cx).search_focused(w, cx)));
}

#[gpui::test]
fn tab_from_the_list_goes_to_the_detail_column(cx: &mut TestAppContext) {
    let (main, mut vcx) = from_search(true, cx);
    tab("tab", &mut vcx);
    tab("tab", &mut vcx);
    let (in_list, in_detail) = vcx.update(|w, cx| {
        let m = main.read(cx);
        (
            m.list_focus.contains_focused(w, cx),
            m.detail_focus.contains_focused(w, cx),
        )
    });
    assert!(!in_list, "no row took Tab");
    assert!(in_detail, "Tab moved on to the detail column");
}

#[gpui::test]
fn tab_reaches_an_empty_list(cx: &mut TestAppContext) {
    let (main, mut vcx) = from_search(false, cx);
    tab("tab", &mut vcx);
    assert!(
        list_focused(&main, &mut vcx),
        "the empty list still takes Tab"
    );
    tab("down", &mut vcx);
    assert!(list_focused(&main, &mut vcx));
    assert!(vcx.update(|_, cx| main.read(cx).state.read(cx).selection.is_none()));
}

/// Focus into the list while a New item is open never raises the discard guard.
#[gpui::test]
fn tab_into_the_list_while_creating_keeps_the_edit(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.begin_new(crate::templates::Template::Login, String::new(), cx);
        // Typed into: leaving now would need the "Discard changes?" prompt.
        s.edit(cx, |b| {
            b.set_title("Bank".into());
        });
        s.selection = None;
    });
    vcx.update(|w, _| w.activate_window());
    vcx.simulate_keystrokes("cmd-f");
    tab("tab", &mut vcx);
    assert!(list_focused(&main, &mut vcx), "Tab lands on the list");
    state.read_with(&vcx, |s, _| {
        assert!(
            s.edit_buffer().is_some_and(|b| b.has_changes()),
            "still editing"
        );
        assert!(s.discard_prompt.is_none(), "no discard prompt");
        assert!(s.selection.is_none(), "selection untouched");
    });
}

/// A clicked row stays selected when the click also focuses the list.
#[gpui::test]
fn clicked_row_survives_the_list_taking_focus(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    vcx.update(|w, _| w.activate_window());
    vcx.simulate_keystrokes("cmd-f");
    vcx.run_until_parked();
    // The last of the three items, so not the first row the listener would pick.
    let (id, ix) = state.read_with(&vcx, |s, _| {
        let id = *s.listing.items.last().unwrap();
        (id, s.listing.row_of(id).unwrap())
    });
    assert!(ix >= 2);
    state.update(&mut vcx, |s, _| s.selection = None);
    let row = main.read_with(&vcx, |m, _| m.list_state.bounds_for_item(ix).unwrap());
    vcx.simulate_click(row.center(), gpui::Modifiers::none());
    tab("", &mut vcx);
    assert!(list_focused(&main, &mut vcx), "the click focused the list");
    assert_eq!(state.read_with(&vcx, |s, _| s.selection), Some(id));
    // gpui focuses on mouse down and selects on mouse up; re-entering by Tab is the
    // case where the listener sees the clicked row already selected.
    vcx.simulate_keystrokes("cmd-f");
    tab("tab", &mut vcx);
    assert!(list_focused(&main, &mut vcx));
    assert_eq!(state.read_with(&vcx, |s, _| s.selection), Some(id));
}
