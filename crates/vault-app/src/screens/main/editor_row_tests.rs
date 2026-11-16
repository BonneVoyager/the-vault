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

/// ↑/↓ are drawn only on the hovered row and the row holding focus; the trash always.
/// Tab from a value input reaches the row's ↑, and Space on it moves the row with
/// focus (and the arrows) following it.
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

    // Focus in row 2's name input.
    let name = name_input(&main, keys[2], &mut vcx);
    vcx.update(|window, cx| ui::focus_input(&name, window, cx));
    vcx.run_until_parked();
    assert_eq!(arrows_on(&mut vcx, &keys), [false, false, true, false]);

    // Keyboard: from row 2's value input, Tab lands on its ↑ (the eye and chip are
    // not Tab stops), Space moves the row up and ↑ keeps focus at the new index.
    let value = value_input(&main, keys[2], &mut vcx);
    vcx.update(|window, cx| ui::focus_input(&value, window, cx));
    vcx.update(|w, _| w.refresh());
    vcx.run_until_parked();
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
