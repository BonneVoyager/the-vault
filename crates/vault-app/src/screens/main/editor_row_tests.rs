//! 05 §2.3 "Edit-mode field rows" (owner 2026-11-15, option A): edit rows mirror read
//! mode's `detail::field_row`, so pressing Edit moves nothing; ↑/↓ show on the hovered
//! or focused row only; the accent ring is drawn on the focused input, never the row.

use gpui::{Bounds, Modifiers, Pixels, TestAppContext, VisualTestContext, point};
use vault_core::SecretString;

use super::tests::{insert_and_select, leak, name_input, open, press, value_input};
use super::*;

/// A tagged item whose rows are all one line in both modes (no meter, no history).
fn plain_item(state: &Entity<AppState>, vcx: &mut VisualTestContext) {
    let device = state.read_with(vcx, |s, _| s.device_id());
    let mut item = vault_core::Item::new("Rows", device, 1);
    item.tags = vec!["work".into()];
    item.fields = [
        ("Username", FieldKind::Text, "chris"),
        ("Website", FieldKind::Url, "https://example.com"),
        ("Email", FieldKind::Email, "c@example.com"),
        ("PIN", FieldKind::Pin, "1234"),
    ]
    .map(|(n, k, v)| vault_core::Field::new(n, k, SecretString::new(v.into()), 1))
    .to_vec();
    insert_and_select(state, item, vcx);
}

fn bounds(vcx: &mut VisualTestContext, selector: String) -> Bounds<Pixels> {
    vcx.debug_bounds(leak(selector.clone()))
        .unwrap_or_else(|| panic!("{selector} not drawn"))
}

fn near(a: Bounds<Pixels>, b: Bounds<Pixels>) -> bool {
    let d = |x: Pixels, y: Pixels| (x - y).abs() < px(0.5);
    d(a.left(), b.left()) && d(a.top(), b.top()) && d(a.right(), b.right()) && {
        d(a.bottom(), b.bottom())
    }
}

/// Read-mode row and label bounds, then edit-mode ones, in field order.
type Measured = Vec<(Bounds<Pixels>, Bounds<Pixels>)>;

fn read_then_edit(
    state: &Entity<AppState>,
    vcx: &mut VisualTestContext,
) -> (Measured, Measured, Vec<u64>) {
    let n = state.read_with(vcx, |s, _| s.viewed_item().unwrap().fields.len());
    let read: Measured = (0..n)
        .map(|ix| {
            (
                bounds(vcx, format!("field-row {ix}")),
                bounds(vcx, format!("field-label {ix}")),
            )
        })
        .collect();
    state.update(vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    let edit: Measured = keys
        .iter()
        .map(|k| {
            (
                bounds(vcx, format!("edit-row {k}")),
                bounds(vcx, format!("edit-label {k}")),
            )
        })
        .collect();
    (read, edit, keys)
}

/// Pressing Edit does not move or resize any row: same bounds in both modes.
#[gpui::test]
fn rows_do_not_move_between_read_and_edit(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    plain_item(&state, &mut vcx);
    let (read, edit, _) = read_then_edit(&state, &mut vcx);
    for (ix, ((r, _), (e, _))) in read.iter().zip(&edit).enumerate() {
        assert!(near(*r, *e), "row {ix}: read {r:?} edit {e:?}");
    }
}

/// The label column has read mode's width and left edge, wide and narrow.
#[gpui::test]
fn label_column_matches_read_mode(cx: &mut TestAppContext) {
    for width in [1200., 760.] {
        let dir = tempfile::tempdir().unwrap();
        let (state, _main, mut vcx) = open(dir.path(), cx);
        vcx.simulate_resize(gpui::size(px(width), px(900.)));
        plain_item(&state, &mut vcx);
        let (read, edit, _) = read_then_edit(&state, &mut vcx);
        for (ix, ((_, r), (_, e))) in read.iter().zip(&edit).enumerate() {
            assert!(
                (r.size.width - e.size.width).abs() < px(0.5)
                    && (r.left() - e.left()).abs() < px(0.5),
                "label {ix} at {width}: read {r:?} edit {e:?}"
            );
        }
    }
}

fn arrows_on(vcx: &mut VisualTestContext, keys: &[u64]) -> Vec<bool> {
    keys.iter()
        .map(|k| {
            let up = vcx.debug_bounds(leak(format!("move-up {k}"))).is_some();
            let down = vcx.debug_bounds(leak(format!("move-down {k}"))).is_some();
            assert_eq!(up, down, "row {k}: both arrows or neither");
            up
        })
        .collect()
}

/// ↑/↓ are drawn only on the hovered row or while one of them has keyboard focus, never
/// for a focused name or value input; the trash always. Tab from a value input reaches
/// the row's (hidden) ↑, which then shows, and Space on it moves the row with focus and
/// the arrows following it.
#[gpui::test]
fn arrows_show_on_hover_and_focus_only(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    vcx.update(|w, _| w.activate_window());
    plain_item(&state, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    // Session start focuses the title: no row is focused or hovered.
    assert_eq!(arrows_on(&mut vcx, &keys), [false; 4]);
    for k in &keys {
        let trash = format!("remove-field {k}");
        assert!(
            vcx.debug_bounds(leak(trash)).is_some(),
            "trash always drawn"
        );
    }

    // Hover row 1, then leave the rows.
    let row1 = bounds(&mut vcx, format!("edit-row {}", keys[1])).center();
    vcx.simulate_mouse_move(row1, None, Modifiers::none());
    vcx.run_until_parked();
    assert_eq!(arrows_on(&mut vcx, &keys), [false, true, false, false]);
    let header = vcx.debug_bounds("editor-header").unwrap().center();
    vcx.simulate_mouse_move(header, None, Modifiers::none());
    vcx.run_until_parked();
    assert_eq!(arrows_on(&mut vcx, &keys), [false; 4]);

    // Focus in row 2's name input, then its value input: no arrows.
    let name = name_input(&main, keys[2], &mut vcx);
    vcx.update(|window, cx| ui::focus_input(&name, window, cx));
    vcx.run_until_parked();
    assert_eq!(arrows_on(&mut vcx, &keys), [false; 4], "name focus");

    // Keyboard: from row 2's value input, Tab lands on its ↑ (the eye and chip are
    // not Tab stops), Space moves the row up and ↑ keeps focus at the new index.
    let value = value_input(&main, keys[2], &mut vcx);
    vcx.update(|window, cx| ui::focus_input(&value, window, cx));
    vcx.update(|w, _| w.refresh());
    vcx.run_until_parked();
    assert_eq!(arrows_on(&mut vcx, &keys), [false; 4], "value focus");
    press(&mut vcx, "tab");
    let up_focused = |vcx: &mut VisualTestContext| {
        vcx.update(|window, cx| {
            let editor = main.read(cx).editor.read(cx);
            let row = editor.rows.iter().find(|r| r.key == keys[2]).unwrap();
            row.up.is_focused(window)
        })
    };
    assert!(up_focused(&mut vcx), "Tab reaches ↑");
    assert_eq!(arrows_on(&mut vcx, &keys), [false, false, true, false]);
    press(&mut vcx, "space");
    let order = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    assert_eq!(order, [keys[0], keys[2], keys[1], keys[3]], "moved up");
    assert!(up_focused(&mut vcx), "focus follows the row");
    assert_eq!(arrows_on(&mut vcx, &keys), [false, false, true, false]);
}

/// Quads painted with the theme's ring colour as a border.
fn ring_quads(vcx: &mut VisualTestContext) -> Vec<Bounds<Pixels>> {
    vcx.update(|window, cx| {
        let ring = cx.theme().ring;
        let scale = window.scale_factor();
        window
            .painted_quads()
            .into_iter()
            .filter(|q| q.border_color == ring && q.border_widths.left.0 > 0.)
            .map(|q| {
                let b = q.bounds;
                Bounds::new(
                    point(px(b.origin.x.0 / scale), px(b.origin.y.0 / scale)),
                    gpui::size(px(b.size.width.0 / scale), px(b.size.height.0 / scale)),
                )
            })
            .collect()
    })
}

/// A focused name or value input draws the accent ring around itself; the row never
/// does, and an unfocused input has none.
#[gpui::test]
fn focused_input_has_the_ring_and_the_row_does_not(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    vcx.update(|w, _| w.activate_window());
    plain_item(&state, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let key = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys[0]);
    let inside = |outer: Bounds<Pixels>, inner: Bounds<Pixels>| {
        inner.left() >= outer.left() - px(1.)
            && inner.right() <= outer.right() + px(1.)
            && inner.top() >= outer.top() - px(1.)
            && inner.bottom() <= outer.bottom() + px(1.)
    };
    let row = bounds(&mut vcx, format!("edit-row {key}"));
    let in_row = |vcx: &mut VisualTestContext| {
        ring_quads(vcx)
            .into_iter()
            .filter(|q| inside(row, *q))
            .collect::<Vec<_>>()
    };
    assert!(in_row(&mut vcx).is_empty(), "no ring while unfocused");

    for (input, selector) in [
        (name_input(&main, key, &mut vcx), format!("edit-name {key}")),
        (
            value_input(&main, key, &mut vcx),
            format!("edit-value {key}"),
        ),
    ] {
        vcx.update(|window, cx| ui::focus_input(&input, window, cx));
        vcx.update(|w, _| w.refresh());
        vcx.run_until_parked();
        let holder = bounds(&mut vcx, selector.clone());
        let rings = in_row(&mut vcx);
        assert!(!rings.is_empty(), "{selector}: ring drawn");
        for q in rings {
            assert!(
                inside(holder, q),
                "{selector}: ring {q:?} outside {holder:?}"
            );
            assert!(!near(q, row), "{selector}: the row has the ring");
        }
    }
}

/// Row keys restart per edit: a row hovered when an edit ends does not light the row
/// with the same key in the next item's edit when nothing is under the pointer.
#[gpui::test]
fn hover_does_not_carry_into_the_next_edit(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    plain_item(&state, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    let row1 = bounds(&mut vcx, format!("edit-row {}", keys[1])).center();
    vcx.simulate_mouse_move(row1, None, Modifiers::none());
    vcx.run_until_parked();
    assert_eq!(arrows_on(&mut vcx, &keys), [false, true, false, false]);
    // The edit ends under the pointer; the pointer then leaves while no rows exist.
    state.update(&mut vcx, |s, cx| s.cancel_edit(cx));
    vcx.run_until_parked();
    let header = vcx.debug_bounds("detail-header").unwrap().center();
    vcx.simulate_mouse_move(header, None, Modifiers::none());
    vcx.run_until_parked();

    plain_item(&state, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let next = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    assert!(next.contains(&keys[1]), "keys restart per edit");
    assert!(
        main.read_with(&vcx, |m, cx| m.editor.read(cx).hovered.is_none()),
        "stale hover kept"
    );
    assert_eq!(arrows_on(&mut vcx, &next), [false; 4]);
}

/// A click on ↓ moves the row out from under the pointer: afterwards only the row the
/// pointer is over shows arrows, not the moved row, even though its value input (which
/// moves with it) holds focus. The click does not focus the ↓ (gpui-component Buttons
/// prevent focus on mouse down).
#[gpui::test]
fn click_move_shows_arrows_only_under_the_pointer(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    vcx.update(|w, _| w.activate_window());
    plain_item(&state, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    let value = value_input(&main, keys[1], &mut vcx);
    vcx.update(|window, cx| ui::focus_input(&value, window, cx));
    let row1 = bounds(&mut vcx, format!("edit-row {}", keys[1])).center();
    vcx.simulate_mouse_move(row1, None, Modifiers::none());
    vcx.run_until_parked();
    let down = bounds(&mut vcx, format!("move-down {}", keys[1])).center();
    vcx.simulate_click(down, Modifiers::none());
    vcx.run_until_parked();

    let order = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    assert_eq!(order, [keys[0], keys[2], keys[1], keys[3]], "moved down");
    let under = vcx
        .debug_bounds(leak(format!("edit-row {}", keys[2])))
        .unwrap();
    assert!(
        under.contains(&down),
        "the swapped row is under the pointer"
    );
    let (down_focused, value_focused) = vcx.update(|window, cx| {
        let editor = main.read(cx).editor.read(cx);
        let row = editor.rows.iter().find(|r| r.key == keys[1]).unwrap();
        let value = gpui::Focusable::focus_handle(&value, cx);
        (row.down.is_focused(window), value.is_focused(window))
    });
    assert!(!down_focused, "a click does not focus ↓");
    assert!(value_focused, "the moved row's value input keeps focus");
    assert_eq!(
        arrows_on(&mut vcx, &keys),
        [false, false, true, false],
        "arrows on the row under the pointer only"
    );
    assert_eq!(
        main.read_with(&vcx, |m, cx| m.editor.read(cx).hovered),
        Some(keys[2])
    );
}

/// The edit-mode title input draws the title at read mode's size and weight: the drawn
/// width of "Rows" in the input equals that line shaped in the read title's style.
#[gpui::test]
fn edit_title_matches_the_read_title_size(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    plain_item(&state, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let (advance, expected, base) = vcx.update(|window, cx| {
        let title = main.read(cx).editor.read(cx).title.clone();
        let drawn = title
            .read(cx)
            .range_to_bounds(&(0.."Rows".len()))
            .expect("title laid out");
        let shape = |el: gpui::StyleRefinement, window: &mut Window| {
            let mut style = window.text_style();
            gpui::Refineable::refine(&mut style, &el.text);
            let size = style.font_size.to_pixels(window.rem_size());
            let run = style.to_run("Rows".len());
            window
                .text_system()
                .shape_line("Rows".into(), size, &[run], None)
                .width
        };
        let read = super::super::detail::title_text(Holder::default()).0;
        let plain = Holder::default().0;
        (drawn.size.width, shape(read, window), shape(plain, window))
    });
    assert!(
        (expected - base).abs() > px(1.),
        "the check tells sizes apart"
    );
    assert!(
        (advance - expected).abs() < px(1.),
        "title advance {advance:?}, read style {expected:?} (plain {base:?})"
    );
}

/// A bare `Styled` to read a style helper's refinement back.
#[derive(Default)]
struct Holder(gpui::StyleRefinement);

impl gpui::Styled for Holder {
    fn style(&mut self) -> &mut gpui::StyleRefinement {
        &mut self.0
    }
}

/// Keys of the rows showing a move flash.
fn flashing(vcx: &mut VisualTestContext, keys: &[u64]) -> Vec<u64> {
    keys.iter()
        .copied()
        .filter(|k| vcx.debug_bounds(leak(format!("move-flash {k}"))).is_some())
        .collect()
}

/// The fill painted for row `key`'s flash: accent hue, its alpha.
fn flash_alpha(vcx: &mut VisualTestContext, key: u64) -> f32 {
    let area = bounds(vcx, format!("move-flash {key}"));
    vcx.update(|window, cx| {
        let accent = cx.theme().primary;
        let area = area.scale(window.scale_factor());
        let close = |a: gpui::ScaledPixels, b: gpui::ScaledPixels| (a.0 - b.0).abs() < 1.;
        let fill = window
            .painted_quads()
            .into_iter()
            .filter(|q| {
                close(q.bounds.origin.x, area.origin.x)
                    && close(q.bounds.origin.y, area.origin.y)
                    && close(q.bounds.size.width, area.size.width)
                    && close(q.bounds.size.height, area.size.height)
            })
            .find_map(|q| q.background.as_solid())
            .expect("flash fill painted");
        assert!(
            (fill.h - accent.h).abs() < 0.01
                && (fill.s - accent.s).abs() < 0.01
                && (fill.l - accent.l).abs() < 0.01,
            "fill {fill:?} is not the accent {accent:?}"
        );
        fill.a
    })
}

/// An item in edit mode, row 1 hovered; returns the row keys.
fn editing_with_hover(state: &Entity<AppState>, vcx: &mut VisualTestContext) -> Vec<u64> {
    plain_item(state, vcx);
    state.update(vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    let row1 = bounds(vcx, format!("edit-row {}", keys[1])).center();
    vcx.simulate_mouse_move(row1, None, Modifiers::none());
    vcx.run_until_parked();
    keys
}

fn click_down(vcx: &mut VisualTestContext, key: u64) {
    let down = bounds(vcx, format!("move-down {key}")).center();
    vcx.simulate_click(down, Modifiers::none());
    vcx.run_until_parked();
}

fn advance(vcx: &mut VisualTestContext, ms: u64) {
    vcx.executor()
        .advance_clock(std::time::Duration::from_millis(ms));
    vcx.run_until_parked();
}

/// 05 "Move flash": a click on ↓ flashes the moved row only, in the accent at up to
/// 18 %; a second move restarts it on that row; its timer removes the fill 900 ms
/// after the last move. Afterwards the editor re-renders no more than with no flash
/// ever shown, and no animation frame is requested. The fade's own progress runs on
/// real time and is not exercised here.
#[gpui::test]
fn click_move_flash_moves_with_a_second_move_and_its_timer_ends_it(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let keys = editing_with_hover(&state, &mut vcx);
    let renders =
        |vcx: &mut VisualTestContext| main.read_with(vcx, |m, cx| m.editor.read(cx).renders);
    let start = renders(&mut vcx);
    advance(&mut vcx, 2_000);
    let baseline = renders(&mut vcx) - start;
    click_down(&mut vcx, keys[1]);
    assert_eq!(flashing(&mut vcx, &keys), [keys[1]]);
    let a = flash_alpha(&mut vcx, keys[1]);
    assert!(a > 0. && a <= 0.18 + 1e-3, "alpha {a}");

    // The row now under the pointer (keys[2]) moves down too: the flash moves with it.
    advance(&mut vcx, 400);
    click_down(&mut vcx, keys[2]);
    assert_eq!(
        flashing(&mut vcx, &keys),
        [keys[2]],
        "restarted on the new row"
    );
    advance(&mut vcx, 600);
    assert_eq!(
        flashing(&mut vcx, &keys),
        [keys[2]],
        "the first timer did not end it"
    );
    advance(&mut vcx, 301);
    assert!(flashing(&mut vcx, &keys).is_empty(), "gone after 900 ms");

    let before = renders(&mut vcx);
    advance(&mut vcx, 2_000);
    assert_eq!(
        renders(&mut vcx) - before,
        baseline,
        "no extra re-renders after the flash"
    );
    assert_no_frame_loop(&mut vcx);
}

/// Delivers two frames (tests have no frame loop): the first may run a callback left
/// from earlier renders; the second must run none, so no animation keeps requesting
/// frames.
fn assert_no_frame_loop(vcx: &mut VisualTestContext) {
    vcx.update(|window, cx| window.simulate_next_frame(cx));
    vcx.run_until_parked();
    let ran = vcx.update(|window, cx| window.simulate_next_frame(cx));
    assert_eq!(ran, 0, "frames keep being requested");
}

/// A flash in progress ends with the edit: cancelling clears it, and so does starting
/// another item's edit directly (row keys restart, so a stale flash would land on the
/// new item's row with the same key).
#[gpui::test]
fn flash_ends_with_the_edit(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    let flash = |vcx: &mut VisualTestContext| {
        main.read_with(vcx, |m, cx| m.editor.read(cx).flash.map(|f| f.key))
    };

    // Cancel mid-flash.
    let keys = editing_with_hover(&state, &mut vcx);
    click_down(&mut vcx, keys[1]);
    assert_eq!(flash(&mut vcx), Some(keys[1]));
    state.update(&mut vcx, |s, cx| s.cancel_edit(cx));
    vcx.run_until_parked();
    assert_eq!(flash(&mut vcx), None, "cleared on cancel");
    assert!(flashing(&mut vcx, &keys).is_empty());
    assert_no_frame_loop(&mut vcx);

    // Another item's edit begins mid-flash, in one update (no read-mode frame between).
    let keys = editing_with_hover(&state, &mut vcx);
    click_down(&mut vcx, keys[1]);
    assert_eq!(flash(&mut vcx), Some(keys[1]));
    let device = state.read_with(&vcx, |s, _| s.device_id());
    let mut other = vault_core::Item::new("Other", device, 1);
    other.fields = (0..4)
        .map(|i| {
            let v = SecretString::new("v".into());
            vault_core::Field::new(format!("f{i}"), FieldKind::Text, v, 1)
        })
        .collect();
    let other_id = state.update(&mut vcx, |s, _| {
        let id = s
            .vault
            .as_mut()
            .unwrap()
            .edit(|v| v.insert(other, 10))
            .unwrap();
        s.vault_changed();
        id
    });
    state.update(&mut vcx, |s, cx| {
        s.cancel_edit(cx);
        s.select(other_id, cx);
        s.begin_edit(cx);
    });
    vcx.run_until_parked();
    let next = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    assert!(next.contains(&keys[1]), "keys restart per edit");
    assert_eq!(flash(&mut vcx), None, "cleared for the new edit");
    assert!(flashing(&mut vcx, &next).is_empty());
    assert_no_frame_loop(&mut vcx);
}

/// A keyboard move (Space on a focused ↑) does not flash.
#[gpui::test]
fn keyboard_move_does_not_flash(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(dir.path(), cx);
    vcx.update(|w, _| w.activate_window());
    let keys = editing_with_hover(&state, &mut vcx);
    let value = value_input(&main, keys[2], &mut vcx);
    vcx.update(|window, cx| ui::focus_input(&value, window, cx));
    vcx.update(|w, _| w.refresh());
    vcx.run_until_parked();
    press(&mut vcx, "tab");
    press(&mut vcx, "space");
    let order = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    assert_eq!(order, [keys[0], keys[2], keys[1], keys[3]], "moved up");
    assert!(flashing(&mut vcx, &keys).is_empty());
}

/// Under Reduce Motion the fill is solid 18 % for 300 ms, then gone (no fade).
#[gpui::test]
fn reduce_motion_flash_is_solid_for_300_ms(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    state.update(&mut vcx, |s, cx| s.set_reduce_motion(true, cx));
    let keys = editing_with_hover(&state, &mut vcx);
    click_down(&mut vcx, keys[1]);
    assert!(
        (flash_alpha(&mut vcx, keys[1]) - 0.18).abs() < 1e-3,
        "solid"
    );
    advance(&mut vcx, 299);
    assert!(
        (flash_alpha(&mut vcx, keys[1]) - 0.18).abs() < 1e-3,
        "still solid"
    );
    advance(&mut vcx, 2);
    assert!(flashing(&mut vcx, &keys).is_empty(), "cleared at 300 ms");
}

/// A drop flashes the dropped row.
#[gpui::test]
fn drop_flashes_the_dropped_row(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _main, mut vcx) = open(dir.path(), cx);
    plain_item(&state, &mut vcx);
    state.update(&mut vcx, |s, cx| s.begin_edit(cx));
    vcx.run_until_parked();
    let keys = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    let none = Modifiers::none();
    let grip = bounds(&mut vcx, format!("grip {}", keys[0])).center();
    vcx.simulate_mouse_down(grip, gpui::MouseButton::Left, none);
    vcx.simulate_mouse_move(grip + point(px(0.), px(6.)), gpui::MouseButton::Left, none);
    vcx.run_until_parked();
    let b = bounds(&mut vcx, format!("edit-row {}", keys[2]));
    let at = point(b.center().x, b.top() + b.size.height * 0.75);
    vcx.simulate_mouse_move(at, gpui::MouseButton::Left, none);
    vcx.run_until_parked();
    assert!(
        flashing(&mut vcx, &keys).is_empty(),
        "no flash while dragging"
    );
    vcx.simulate_mouse_up(at, gpui::MouseButton::Left, none);
    vcx.run_until_parked();
    let order = state.read_with(&vcx, |s, _| s.edit_buffer().unwrap().keys.clone());
    assert_eq!(
        order,
        [keys[1], keys[2], keys[0], keys[3]],
        "dropped after row 2"
    );
    assert_eq!(flashing(&mut vcx, &keys), [keys[0]]);
    let a = flash_alpha(&mut vcx, keys[0]);
    assert!(a > 0. && a <= 0.18 + 1e-3, "alpha {a}");
}
