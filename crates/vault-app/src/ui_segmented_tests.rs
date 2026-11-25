//! `ui::segmented`: colours in both appearances, sizes at every text scale, click and
//! ←/→ selection, focus and the focus ring.

use std::cell::RefCell;
use std::rc::Rc;

use gpui::{
    AppContext as _, Bounds, Context, Hsla, InteractiveElement as _, IntoElement, Modifiers,
    ParentElement as _, Pixels, Render, Styled as _, TestAppContext, VisualTestContext, Window,
    WindowHandle, point, px,
};
use gpui_component::{ActiveTheme as _, Root};

use super::{SEGMENT_PILL_H, SEGMENT_TRACK_H, segmented};
use crate::state::Appearance;
use crate::theme::{ThemePrefs, VaultTheme, apply};

/// Three segments A, B, C with `selected` chosen, then another Tab stop ("other");
/// logs every `on_select`.
struct Control {
    selected: usize,
    log: Rc<RefCell<Vec<usize>>>,
}

impl Render for Control {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        super::update_focus_ring(window, cx);
        let log = self.log.clone();
        super::clear_focus_ring_on_click(gpui::div().id("test-root").p_4().gap_4().flex())
            .child(
                segmented("test-seg", ["A", "B", "C"], self.selected)
                    .selector("seg")
                    .aria_label("Test")
                    .on_select(move |ix, _, _| log.borrow_mut().push(ix)),
            )
            .child(
                gpui::div()
                    .id("other")
                    .tab_index(0)
                    .size_8()
                    .debug_selector(|| "other".into()),
            )
    }
}

struct Setup {
    appearance: Appearance,
    selected: usize,
    scale: f32,
}

const DARK: Setup = Setup {
    appearance: Appearance::Dark,
    selected: 1,
    scale: 1.,
};

fn open(
    setup: Setup,
    cx: &mut TestAppContext,
) -> (Rc<RefCell<Vec<usize>>>, &mut VisualTestContext) {
    cx.update(gpui_component::init);
    cx.update(|cx| {
        cx.set_global(ThemePrefs {
            appearance: setup.appearance,
            scale: setup.scale,
        })
    });
    let log = Rc::new(RefCell::new(Vec::new()));
    let view_log = log.clone();
    let window: WindowHandle<Root> = cx.add_window(|window, cx| {
        apply(window, cx);
        let view = cx.new(|_| Control {
            selected: setup.selected,
            log: view_log,
        });
        Root::new(view, window, cx)
    });
    let vcx = VisualTestContext::from_window(window.into(), cx).into_mut();
    vcx.run_until_parked();
    (log, vcx)
}

fn same(a: Bounds<gpui::ScaledPixels>, b: Bounds<gpui::ScaledPixels>) -> bool {
    let d = |a: f32, b: f32| (a - b).abs() < 0.5;
    d(a.origin.x.0, b.origin.x.0)
        && d(a.origin.y.0, b.origin.y.0)
        && d(a.size.width.0, b.size.width.0)
        && d(a.size.height.0, b.size.height.0)
}

/// Solid fills of the quads painted exactly on `selector`'s bounds.
fn fills_on(selector: &'static str, vcx: &mut VisualTestContext) -> Vec<Hsla> {
    let area = vcx.debug_bounds(selector).expect("segment rendered");
    vcx.update(|window, _| {
        let area = area.scale(window.scale_factor());
        window
            .painted_quads()
            .into_iter()
            .filter(|q| same(q.bounds, area))
            .filter_map(|q| q.background.as_solid())
            .collect()
    })
}

/// The track's fill and border colours (gpui paints them as separate quads).
fn track_colours(vcx: &mut VisualTestContext) -> (Hsla, Hsla) {
    let area = vcx.debug_bounds("seg-track").expect("track");
    vcx.update(|window, _| {
        let area = area.scale(window.scale_factor());
        let quads: Vec<_> = window
            .painted_quads()
            .into_iter()
            .filter(|q| same(q.bounds, area))
            .collect();
        let fill = quads
            .iter()
            .find_map(|q| q.background.as_solid().filter(|c| c.a > 0.))
            .expect("track fill");
        let border = quads
            .iter()
            .rev()
            .find(|q| q.border_widths.left.0 > 0.)
            .map(|q| q.border_color)
            .expect("track border");
        (fill, border)
    })
}

/// Whether the track paints the focus ring colour on its border.
fn ring_shown(vcx: &mut VisualTestContext) -> bool {
    let area = vcx.debug_bounds("seg-track").expect("track");
    vcx.update(|window, cx| {
        let ring = cx.theme().ring;
        let area = area.scale(window.scale_factor());
        window
            .painted_quads()
            .into_iter()
            .any(|q| same(q.bounds, area) && q.border_widths.left.0 > 0. && q.border_color == ring)
    })
}

fn hex(value: u32) -> Hsla {
    gpui::rgb(value).into()
}

fn click(selector: &'static str, vcx: &mut VisualTestContext) {
    let at = vcx.debug_bounds(selector).expect(selector).center();
    click_at(at, vcx);
}

fn click_at(at: gpui::Point<Pixels>, vcx: &mut VisualTestContext) {
    vcx.simulate_click(at, Modifiers::none());
    vcx.run_until_parked();
}

/// Keyboard focus on the control: click the other Tab stop, then Shift-Tab back (with
/// nothing focused, gpui-component's Root never sees Tab).
fn tab_in(vcx: &mut VisualTestContext) {
    click("other", vcx);
    let other = vcx.update(|window, cx| window.focused(cx));
    assert!(other.is_some(), "the other element took focus");
    vcx.simulate_keystrokes("shift-tab");
    vcx.run_until_parked();
    let now = vcx.update(|window, cx| window.focused(cx));
    assert!(
        now.is_some() && now != other,
        "Shift-Tab reached the control"
    );
}

/// Owner decision 2026-11-25 (option B): dark track #2A2A2D with a #3A3A3E pill.
#[gpui::test]
fn dark_selected_segment_is_the_lighter_pill(cx: &mut TestAppContext) {
    let (_, vcx) = open(DARK, cx);
    let dark = VaultTheme::for_appearance(true);
    assert!(vcx.update(|_, cx| cx.theme().is_dark()));
    assert_eq!(dark.segment_selected, hex(0x3A3A3E));
    assert_eq!(fills_on("seg: B", vcx), vec![dark.segment_selected]);
    assert!(fills_on("seg: A", vcx).is_empty(), "unselected: no fill");
    let (fill, border) = track_colours(vcx);
    assert_eq!((fill, border), (dark.bg_elevated, dark.border));
    assert_ne!(fill, dark.bg, "track stands out from the window");
}

/// Light: #F7F7F8 track with a white pill.
#[gpui::test]
fn light_selected_segment_is_white(cx: &mut TestAppContext) {
    let (_, vcx) = open(
        Setup {
            appearance: Appearance::Light,
            ..DARK
        },
        cx,
    );
    let light = VaultTheme::for_appearance(false);
    assert!(!vcx.update(|_, cx| cx.theme().is_dark()));
    assert_eq!(light.segment_selected, hex(0xFFFFFF));
    assert_eq!(fills_on("seg: B", vcx), vec![light.segment_selected]);
    assert!(fills_on("seg: C", vcx).is_empty(), "unselected: no fill");
    let (fill, border) = track_colours(vcx);
    assert_eq!((fill, border), (light.bg_elevated, light.border));
}

/// Review 2026-11-25: the pill grows with the track at every text size (Larger
/// included), so it never sits cramped in a taller track.
#[gpui::test]
fn segmented_sizes_follow_text_size(cx: &mut TestAppContext) {
    for scale in [1., 1.15, 1.3] {
        let (_, vcx) = open(Setup { scale, ..DARK }, cx);
        let track = vcx
            .debug_bounds("seg-track")
            .expect("track")
            .size
            .height
            .as_f32();
        let pill = vcx
            .debug_bounds("seg: B")
            .expect("pill")
            .size
            .height
            .as_f32();
        // Layout snaps to device pixels (0.5 pt on the 2x test window).
        assert!(
            (track - SEGMENT_TRACK_H * scale).abs() <= 0.5,
            "{scale}: track {track}"
        );
        let ratio = pill / track;
        assert!(
            (ratio - SEGMENT_PILL_H / SEGMENT_TRACK_H).abs() < 0.02,
            "{scale}: pill {pill} in track {track}"
        );
    }
}

/// A click reports the segment's index; re-clicking the selected one reports nothing.
/// Clicks on segments and on the track's padding leave focus where it was.
#[gpui::test]
fn segmented_click_selects_without_taking_focus(cx: &mut TestAppContext) {
    let (log, vcx) = open(DARK, cx);
    click("other", vcx);
    let before = vcx.update(|window, cx| window.focused(cx));
    assert!(before.is_some(), "the other element took focus");
    for selector in ["seg: C", "seg: B", "seg: A"] {
        click(selector, vcx);
    }
    let track = vcx.debug_bounds("seg-track").expect("track");
    click_at(point(track.origin.x + px(1.5), track.center().y), vcx);
    assert_eq!(*log.borrow(), vec![2, 0]);
    assert_eq!(vcx.update(|window, cx| window.focused(cx)), before);
}

/// Tab reaches the control; ←/→ step the selection from the current one; modified
/// arrows do nothing; arrows do nothing while unfocused.
#[gpui::test]
fn segmented_arrows_move_the_selection(cx: &mut TestAppContext) {
    let (log, vcx) = open(DARK, cx);
    vcx.simulate_keystrokes("right");
    assert!(log.borrow().is_empty(), "unfocused: arrows do nothing");
    tab_in(vcx);
    for keys in [
        "shift-right",
        "alt-right",
        "cmd-left",
        "ctrl-left",
        "shift-left",
    ] {
        vcx.simulate_keystrokes(keys);
    }
    assert!(log.borrow().is_empty(), "modified arrows do nothing");
    vcx.simulate_keystrokes("right");
    vcx.simulate_keystrokes("left");
    assert_eq!(*log.borrow(), vec![2, 0]);
}

/// ←/→ stop at the ends (no wrap).
#[gpui::test]
fn segmented_arrows_stop_at_the_ends(cx: &mut TestAppContext) {
    for (selected, key, then) in [(0, "left", 1), (2, "right", 1)] {
        let (log, vcx) = open(Setup { selected, ..DARK }, cx);
        tab_in(vcx);
        vcx.simulate_keystrokes(key);
        assert!(log.borrow().is_empty(), "{key} at {selected}");
        let back = if key == "left" { "right" } else { "left" };
        vcx.simulate_keystrokes(back);
        assert_eq!(*log.borrow(), vec![then], "{back} at {selected}");
    }
}

/// An out-of-range `selected` is treated as the last segment.
#[gpui::test]
fn segmented_clamps_the_selection(cx: &mut TestAppContext) {
    let (log, vcx) = open(
        Setup {
            selected: 9,
            ..DARK
        },
        cx,
    );
    assert_eq!(
        fills_on("seg: C", vcx),
        vec![VaultTheme::for_appearance(true).segment_selected]
    );
    tab_in(vcx);
    vcx.simulate_keystrokes("right");
    vcx.simulate_keystrokes("left");
    assert_eq!(*log.borrow(), vec![1]);
}

/// The ring shows after Tab and goes away after a click (05 §6).
#[gpui::test]
fn segmented_ring_after_tab_not_after_click(cx: &mut TestAppContext) {
    let (_, vcx) = open(DARK, cx);
    assert!(!ring_shown(vcx), "no ring before focus");
    tab_in(vcx);
    assert!(ring_shown(vcx), "ring after Tab");
    click("seg: A", vcx);
    assert!(!ring_shown(vcx), "no ring after a click");
}
