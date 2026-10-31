//! Collapsible sidebar (⌃⌘S): state, persistence, collapsed layout, the list's Lock
//! button, menu title, motion and focus.

use std::time::Duration;

use gpui::{AppContext as _, Modifiers, OwnedMenuItem, TestAppContext, VisualTestContext, px};
use gpui_component::Root;

use super::MainScreen;
use super::tests::{PW, open};
use crate::state::{AppState, Filter, Settings};
use crate::ui::probe::Seen;
use crate::{persist, ui};
use vault_core::SecretString;

/// Lets a running slide finish: the animation runs on real time and ends itself on
/// its last frame (t = 1), which the next frame then settles.
fn settle(vcx: &mut VisualTestContext) {
    std::thread::sleep(ui::SIDEBAR_MOTION + Duration::from_millis(30));
    frame(vcx);
    frame(vcx);
}

fn has(selector: &'static str, vcx: &mut VisualTestContext) -> bool {
    vcx.debug_bounds(selector).is_some()
}

fn bounds(selector: &'static str, vcx: &mut VisualTestContext) -> gpui::Bounds<gpui::Pixels> {
    vcx.debug_bounds(selector)
        .unwrap_or_else(|| panic!("{selector} not rendered"))
}

fn visible(state: &gpui::Entity<AppState>, vcx: &VisualTestContext) -> bool {
    state.read_with(vcx, |s, _| s.sidebar_visible())
}

/// Names of the View menu's action items, as installed on the (test) platform.
fn view_menu(vcx: &mut VisualTestContext) -> Vec<String> {
    let menus = vcx.cx.update(|cx| cx.get_menus()).unwrap_or_default();
    menus
        .into_iter()
        .find(|m| m.name.as_ref() == "View")
        .map(|m| {
            m.items
                .into_iter()
                .filter_map(|item| match item {
                    OwnedMenuItem::Action { name, .. } => Some(name),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The element that has keyboard focus.
fn focused(vcx: &mut VisualTestContext) -> Option<gpui::FocusHandle> {
    vcx.update(|window, cx| window.focused(cx))
}

#[gpui::test]
fn toggle_flips_state_menu_and_persists(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    vcx.cx
        .update(|cx| state.update(cx, |s, cx| crate::actions::refresh_menus(s, cx)));
    // Default: expanded, with the toggle offering to hide it.
    assert!(visible(&state, &vcx));
    assert!(!Settings::default().sidebar_hidden);
    assert!(has("sidebar-toggle Hide Sidebar", &mut vcx));
    assert!(view_menu(&mut vcx).contains(&"Hide Sidebar".to_owned()));

    // The button collapses; the setting, the button and the menu title all follow.
    let toggle = bounds("sidebar-toggle Hide Sidebar", &mut vcx);
    vcx.simulate_click(toggle.center(), Modifiers::none());
    settle(&mut vcx);
    assert!(!visible(&state, &vcx));
    assert!(state.read_with(&vcx, |s, _| s.settings.sidebar_hidden));
    assert!(has("sidebar-toggle Show Sidebar", &mut vcx));
    let menu = view_menu(&mut vcx);
    assert!(menu.contains(&"Show Sidebar".to_owned()), "{menu:?}");
    assert!(!menu.contains(&"Hide Sidebar".to_owned()), "{menu:?}");

    // The window minimum follows: 600 x 520 collapsed.
    assert_eq!(ui::last_main_min_size(), Some((600., 520.)));

    // ⌃⌘S is the binding (the old ⌘⌥S is not) and expands again.
    vcx.simulate_keystrokes("cmd-alt-s");
    assert!(!visible(&state, &vcx), "⌘⌥S no longer toggles");
    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);
    assert!(visible(&state, &vcx));
    assert!(view_menu(&mut vcx).contains(&"Hide Sidebar".to_owned()));
    assert_eq!(ui::last_main_min_size(), Some((820., 520.)));
    assert_eq!(ui::main_min_size(true), (820., 520.));
    assert_eq!(ui::main_min_size(false), (600., 520.));

    // Collapsed state survives a relaunch through settings.json, per app.
    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    let saved = state.read_with(&vcx, |s, _| s.settings.clone());
    let support = tempfile::tempdir().unwrap();
    persist::save_settings_to(support.path(), &saved);
    let loaded = persist::load_settings_from(support.path());
    assert!(loaded.sidebar_hidden);
    let relaunched = vcx.cx.new(|_| {
        AppState::new(vault_core::Uuid::new_v4(), Vec::new(), false).with_settings(loaded)
    });
    assert!(!relaunched.read_with(&vcx, |s, _| s.sidebar_visible()));
}

#[gpui::test]
fn relaunch_collapsed_opens_without_a_sidebar_or_slide(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    settle(&mut vcx);
    // A second main screen over the collapsed state, as at launch.
    let window = vcx.cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|cx| MainScreen::new(state.clone(), None, window, cx));
        Root::new(view, window, cx)
    });
    let mut second = VisualTestContext::from_window(window.into(), &vcx.cx);
    second.run_until_parked();
    assert!(!has("sidebar-slide", &mut second), "no slide at launch");
    assert!(!has("sidebar-column", &mut second));
    assert!(has("sidebar-toggle Show Sidebar", &mut second));
}

#[gpui::test]
fn collapsed_layout_keeps_the_list_width_and_clears_the_traffic_lights(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    let list_before = bounds("list-footer", &mut vcx);
    assert!(has("sidebar-column", &mut vcx));

    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    vcx.run_until_parked();
    // Mid-slide the sidebar is still drawn, clipped.
    assert!(has("sidebar-slide", &mut vcx));
    settle(&mut vcx);

    // Removed from the tree, not squeezed to zero width.
    for gone in [
        "sidebar-slide",
        "sidebar-column",
        "nav All Items icon=LayoutList",
    ] {
        assert!(!has(gone, &mut vcx), "{gone} still rendered");
    }
    // The list keeps its width at the left edge; the detail takes the rest.
    let list = bounds("list-footer", &mut vcx);
    assert_eq!(list.size.width, list_before.size.width);
    assert_eq!(list.left(), px(0.));
    let detail = bounds("detail-column", &mut vcx);
    assert!((detail.left() - list.right()).abs() <= px(1.));
    let window_width = vcx.update(|window, _| window.viewport_size().width);
    assert!((detail.right() - window_width).abs() <= px(1.));

    // The toggle sits right of the traffic lights, still centred in the band.
    let toggle = bounds("sidebar-toggle Show Sidebar", &mut vcx);
    assert_eq!(toggle.left(), px(ui::COLLAPSED_PAD_X));
    assert!(toggle.left() > px(ui::TRAFFIC_LIGHTS_RIGHT));
    let search = bounds("list-search", &mut vcx);
    assert!(search.left() > toggle.right());
    assert!(search.bottom() <= px(ui::TOP_BAND_HEIGHT));
}

#[gpui::test]
fn collapse_keeps_the_filter_and_the_heading_shows_it(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    // Expanded: no heading, the sidebar shows the filter.
    assert!(!has("list-filter-heading", &mut vcx));

    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    settle(&mut vcx);
    assert_eq!(state.read_with(&vcx, |s, _| s.filter.clone()), Filter::All);
    assert!(has("list-filter-title All Items", &mut vcx));
    assert!(has("list-filter-count 3", &mut vcx));
    let heading = bounds("list-filter-heading", &mut vcx);
    assert!(heading.top() >= px(ui::TOP_BAND_HEIGHT) - px(1.));

    // The tag filter as the sidebar spells it, with its count.
    state.update(&mut vcx, |s, cx| {
        s.set_filter(Filter::Tag("INFRA".into()), cx)
    });
    vcx.run_until_parked();
    assert!(has("list-filter-title #infra", &mut vcx));
    assert!(has("list-filter-count 1", &mut vcx));
    state.update(&mut vcx, |s, cx| s.set_filter(Filter::Favorites, cx));
    vcx.run_until_parked();
    assert!(has("list-filter-title Favorites", &mut vcx));
    assert!(has("list-filter-count 0", &mut vcx));

    // Expanding keeps the filter, and the heading goes.
    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);
    assert_eq!(
        state.read_with(&vcx, |s, _| s.filter.clone()),
        Filter::Favorites
    );
    assert!(!has("list-filter-heading", &mut vcx));
    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);
    assert_eq!(
        state.read_with(&vcx, |s, _| s.filter.clone()),
        Filter::Favorites
    );
}

/// No Lock button anywhere in the window, in either sidebar state. Lock is ⌘L and the
/// File menu's "Lock" item, and both lock from either state.
#[gpui::test]
fn lock_is_cmd_l_and_the_file_menu_only(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    vcx.cx
        .update(|cx| state.update(cx, |s, cx| crate::actions::refresh_menus(s, cx)));
    let menus = vcx.cx.update(|cx| cx.get_menus()).unwrap();
    let file = menus
        .iter()
        .find(|m| m.name.as_ref() == "File")
        .expect("File menu");
    let menu_lock = file
        .items
        .iter()
        .find_map(|item| match item {
            OwnedMenuItem::Action { name, action, .. } if name == "Lock" => {
                Some(action.boxed_clone())
            }
            _ => None,
        })
        .expect("File > Lock");
    assert!(menu_lock.partial_eq(&crate::actions::Lock));

    for collapse in [false, true] {
        if collapse {
            state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
            settle(&mut vcx);
        }
        for gone in ["list-lock", "sidebar-lock"] {
            assert!(!has(gone, &mut vcx), "{gone} rendered");
        }
        // ⌘L locks.
        vcx.simulate_keystrokes("cmd-l");
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.locked), "cmd-l");
        state.update(&mut vcx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        // The menu item's own action locks.
        let action = menu_lock.boxed_clone();
        vcx.update(|window, cx| window.dispatch_action(action, cx));
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.locked), "File > Lock");
        state.update(&mut vcx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        assert!(!state.read_with(&vcx, |s, _| s.locked));
    }
}

#[gpui::test]
fn reduce_motion_toggles_instantly(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    state.update(&mut vcx, |s, cx| s.set_reduce_motion(true, cx));
    for _ in 0..2 {
        vcx.simulate_keystrokes("ctrl-cmd-s");
        vcx.run_until_parked();
        assert!(
            !has("sidebar-slide", &mut vcx),
            "no slide under Reduce Motion"
        );
        assert_eq!(has("sidebar-column", &mut vcx), visible(&state, &vcx));
    }
}

#[gpui::test]
fn toggling_keeps_focus_in_search_list_and_editor(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);

    // Search field: by key and by clicking the toggle, then typing still filters.
    vcx.simulate_keystrokes("cmd-f");
    let search = focused(&mut vcx);
    assert!(vcx.update(|window, cx| main.read(cx).search_focused(window, cx)));
    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);
    assert_eq!(focused(&mut vcx), search, "⌃⌘S kept the search focus");
    let toggle = bounds("sidebar-toggle Show Sidebar", &mut vcx);
    vcx.simulate_click(toggle.center(), Modifiers::none());
    settle(&mut vcx);
    assert!(visible(&state, &vcx));
    assert_eq!(
        focused(&mut vcx),
        search,
        "the toggle button kept the search focus"
    );
    vcx.simulate_input("visa");
    assert_eq!(state.read_with(&vcx, |s, _| s.query.clone()), "visa");
    vcx.simulate_input("");
    state.update(&mut vcx, |s, cx| s.set_query(String::new(), cx));
    vcx.run_until_parked();

    // List: ↑/↓ work unchanged while collapsed.
    state.update(&mut vcx, |s, cx| {
        let top = s.listing.items[0];
        s.select(top, cx);
    });
    vcx.simulate_keystrokes("cmd-1 ctrl-cmd-s");
    settle(&mut vcx);
    let first = state.read_with(&vcx, |s, _| s.selection);
    vcx.simulate_keystrokes("down");
    let second = state.read_with(&vcx, |s, _| s.selection);
    assert_ne!(first, second);
    vcx.simulate_keystrokes("up");
    assert_eq!(state.read_with(&vcx, |s, _| s.selection), first);
    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);

    // Editor: the focused title input keeps focus and the edit survives.
    vcx.simulate_keystrokes("cmd-e");
    vcx.run_until_parked();
    let title = focused(&mut vcx);
    assert!(title.is_some());
    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);
    assert_eq!(focused(&mut vcx), title, "the editor kept focus");
    assert!(state.read_with(&vcx, |s, _| s.is_editing()));
    vcx.simulate_input("Z");
    vcx.simulate_keystrokes("cmd-s");
    assert!(state.read_with(&vcx, |s, _| s.selected_item().unwrap().title.ends_with('Z')));
}

/// The heading's count is the sidebar's count for the same filter, also while a search
/// hides some or all of the filter's items.
#[gpui::test]
fn heading_count_matches_the_sidebar_count_after_a_search(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    // "visa" matches the card only: All Items shows 1 row, #infra (GitHub) shows none.
    state.update(&mut vcx, |s, cx| s.set_query("visa".into(), cx));
    vcx.run_until_parked();
    for (filter, label, sidebar, heading) in [
        (
            Filter::All,
            "All Items",
            "nav-count All Items 3",
            "list-filter-count 3",
        ),
        (
            Filter::Tag("infra".into()),
            "#infra",
            "nav-count #infra 1",
            "list-filter-count 1",
        ),
    ] {
        state.update(&mut vcx, |s, cx| s.set_filter(filter.clone(), cx));
        vcx.run_until_parked();
        if filter != Filter::All {
            assert!(
                state.read_with(&vcx, |s, _| s.listing.items.is_empty()),
                "{label}: no visible matches"
            );
        }
        assert!(has(sidebar, &mut vcx), "sidebar shows {sidebar}");
        state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
        settle(&mut vcx);
        let title: &'static str = Box::leak(format!("list-filter-title {label}").into());
        assert!(has(title, &mut vcx), "{title}");
        assert!(has(heading, &mut vcx), "heading shows {heading}");
        state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
        settle(&mut vcx);
    }
}

/// Re-renders the window now (the slide runs on real time, not the test clock).
fn frame(vcx: &mut VisualTestContext) {
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
}

/// Mid-slide, the toggle never passes under the traffic lights (x >= 82) and the
/// search row's inset follows the sidebar's current width.
#[gpui::test]
fn mid_slide_inset_follows_the_sidebar_width(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    let mut widths = Vec::new();
    for _ in 0..2 {
        state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
        for pause in [0, 30, 60, 120] {
            std::thread::sleep(Duration::from_millis(pause));
            frame(&mut vcx);
            let Some(slide) = vcx.debug_bounds("sidebar-slide") else {
                break;
            };
            let toggle = vcx
                .debug_bounds("sidebar-toggle Show Sidebar")
                .or_else(|| vcx.debug_bounds("sidebar-toggle Hide Sidebar"))
                .expect("toggle");
            let width = slide.size.width.as_f32();
            widths.push(width);
            assert!(toggle.left() >= px(ui::COLLAPSED_PAD_X) - px(0.5));
            // The list starts at the sidebar's current right edge; the inset is
            // max(16, 82 - width). Both animations sample the same frame (1 px slack).
            let expected = width + ui::list_header_pad_left(width);
            assert!(
                (toggle.left().as_f32() - expected).abs() <= 1.,
                "toggle at {:?}, sidebar {width}",
                toggle.left()
            );
        }
        settle(&mut vcx);
    }
    assert!(!widths.is_empty(), "sampled the slide");
}

/// Toggling again mid-slide reverses from the current width instead of jumping. The
/// slide clock is pinned, so the width at reversal is known exactly.
#[gpui::test]
fn toggling_mid_slide_reverses_from_the_current_width(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    let sidebar_width = main.read_with(&vcx, |m, _| m.widths[0]);
    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    vcx.run_until_parked();
    let out = main.read_with(&vcx, |m, _| m.slide.clone());
    assert!(!out.showing && !out.is_done(), "collapsing");
    assert_eq!(out.from, 1.);
    assert_eq!(out.duration, ui::SIDEBAR_MOTION);

    // 20 ms into the 180 ms collapse: eased progress 1 - (1 - 1/9)^5.
    let at = Duration::from_millis(20);
    main.update(&mut vcx, |m, _| m.slide_now = Some(out.started + at));
    let progress = 1. - (1. - at.as_secs_f32() / ui::SIDEBAR_MOTION.as_secs_f32()).powi(5);
    let known = 1. - progress;
    assert!((0.5..0.6).contains(&known), "{known}");

    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    vcx.run_until_parked();
    let back = main.read_with(&vcx, |m, _| m.slide.clone());
    assert!(back.showing && !back.is_done(), "expanding");
    // Reverses from the known width (about 122 px of 220), not from 0.
    assert!(
        (back.from - known).abs() < 1e-4,
        "from {} instead of {known}",
        back.from
    );
    assert!((back.from * sidebar_width - known * sidebar_width).abs() < 0.05);
    // Only the remaining distance is travelled, in proportionally less time.
    assert_eq!(back.duration, ui::SIDEBAR_MOTION.mul_f32(1. - back.from));

    settle(&mut vcx);
    assert!(visible(&state, &vcx));
    assert!(has("sidebar-column", &mut vcx));
    assert!(!has("sidebar-slide", &mut vcx));
}

/// Frames until the slide is settled, plus two more; returns every probe record.
fn run_slide(main: &gpui::Entity<MainScreen>, vcx: &mut VisualTestContext) -> Vec<Seen> {
    let mut seen = ui::probe::take();
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(15));
        frame(vcx);
        seen.extend(ui::probe::take());
        if main.read_with(vcx, |m, _| m.slide.is_done()) && !has("sidebar-slide", vcx) {
            break;
        }
    }
    for _ in 0..2 {
        frame(vcx);
        seen.extend(ui::probe::take());
    }
    seen
}

/// The detail column (and its content, inside the fade-in animation) and the list
/// column keep one element-id path and their element state before, during and after
/// a slide either way, so nothing in them remounts or replays its fade-in (the blink:
/// the old layout swapped parents at the slide's start and end).
#[gpui::test]
fn columns_keep_their_identity_across_a_slide(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    frame(&mut vcx);
    let before = ui::probe::take();
    let path_of = |seen: &[Seen], name: &str| {
        seen.iter()
            .rev()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("{name} not rendered"))
            .path
            .clone()
    };
    let names = ["detail-probe", "detail-content-probe", "list-probe"];
    let paths: Vec<String> = names.iter().map(|n| path_of(&before, n)).collect();
    assert!(
        paths[1].contains(".detail."),
        "inside the detail column: {}",
        paths[1]
    );

    for _ in 0..2 {
        state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
        vcx.run_until_parked();
        let seen = run_slide(&main, &mut vcx);
        assert!(seen.len() >= 3 * names.len(), "sampled frames");
        for s in &seen {
            let ix = names.iter().position(|n| *n == s.name).unwrap();
            assert_eq!(s.path, paths[ix], "{} changed identity", s.name);
            assert!(!s.fresh, "{} remounted", s.name);
        }
    }
}

/// Once the slide reports done, no frame puts the list column anywhere but its final
/// x, and on the way there it only moves one way.
#[gpui::test]
fn no_frame_after_the_slide_ends_moves_the_list(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    let sidebar = main.read_with(&vcx, |m, _| m.widths[0]);
    frame(&mut vcx);
    ui::probe::take();
    for (target, collapsing) in [(0., true), (sidebar, false)] {
        state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
        vcx.run_until_parked();
        let mut xs = Vec::new();
        let mut done_at = None;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(15));
            frame(&mut vcx);
            let x = ui::probe::take()
                .into_iter()
                .rev()
                .find(|s| s.name == "list-probe")
                .and_then(|s| s.x)
                .expect("list x")
                .as_f32();
            xs.push(x);
            if done_at.is_none() && main.read_with(&vcx, |m, _| m.slide.is_done()) {
                done_at = Some(xs.len() - 1);
            }
            if done_at.is_some_and(|d| xs.len() > d + 3) {
                break;
            }
        }
        let done_at = done_at.expect("the slide ended on its own");
        for (i, x) in xs.iter().enumerate().skip(done_at) {
            assert!(
                (x - target).abs() < 0.5,
                "frame {i} after done at {x}, not {target}: {xs:?}"
            );
        }
        for pair in xs.windows(2) {
            let step = pair[1] - pair[0];
            assert!(
                if collapsing {
                    step <= 0.01
                } else {
                    step >= -0.01
                },
                "list moved back: {xs:?}"
            );
        }
    }
}

/// Dragging the dividers resizes the sidebar and list columns within their ranges and
/// reports the widths for window.json.
#[gpui::test]
fn dragging_the_dividers_resizes_the_columns(cx: &mut TestAppContext) {
    use gpui::{MouseButton, point};
    let dir = tempfile::tempdir().unwrap();
    let (_, main, mut vcx) = open(true, dir.path(), cx);
    let reported = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = reported.clone();
    let _sub = vcx.update(|_, cx| {
        cx.subscribe(&main, move |_, ev: &super::ColumnsResized, _| {
            sink.borrow_mut().push(ev.0);
        })
    });
    let drag = |selector: &'static str, dx: f32, vcx: &mut VisualTestContext| {
        let at = bounds(selector, vcx).center();
        let to = at + point(px(dx), px(0.));
        vcx.simulate_mouse_down(at, MouseButton::Left, Modifiers::none());
        vcx.simulate_mouse_move(
            at + point(px(dx / 2.), px(0.)),
            MouseButton::Left,
            Modifiers::none(),
        );
        vcx.simulate_mouse_move(to, MouseButton::Left, Modifiers::none());
        vcx.simulate_mouse_up(to, MouseButton::Left, Modifiers::none());
        vcx.run_until_parked();
    };
    let [side, list] = main.read_with(&vcx, |m, _| m.widths);
    drag("column-handle Sidebar", 40., &mut vcx);
    let after = main.read_with(&vcx, |m, _| m.widths);
    assert!((after[0] - (side + 40.)).abs() < 1., "{after:?}");
    assert_eq!(after[1], list);
    drag("column-handle List", -30., &mut vcx);
    let after = main.read_with(&vcx, |m, _| m.widths);
    assert!((after[1] - (list - 30.)).abs() < 1., "{after:?}");
    // Clamped to the ranges.
    drag("column-handle Sidebar", 400., &mut vcx);
    assert_eq!(main.read_with(&vcx, |m, _| m.widths[0]), 320.);
    assert_eq!(
        reported.borrow().last().copied(),
        Some(main.read_with(&vcx, |m, _| m.widths))
    );
    assert!(reported.borrow().len() >= 3, "{:?}", reported.borrow());
}

/// Presses on `selector`, moves `dx` and releases at `release` (default: where it moved).
fn drag_by(
    selector: &'static str,
    dx: f32,
    release: Option<gpui::Point<gpui::Pixels>>,
    vcx: &mut VisualTestContext,
) {
    use gpui::{MouseButton, point};
    let at = bounds(selector, vcx).center();
    let to = at + point(px(dx), px(0.));
    vcx.simulate_mouse_down(at, MouseButton::Left, Modifiers::none());
    vcx.simulate_mouse_move(
        at + point(px(dx / 2.), px(0.)),
        MouseButton::Left,
        Modifiers::none(),
    );
    vcx.simulate_mouse_move(to, MouseButton::Left, Modifiers::none());
    vcx.simulate_mouse_up(release.unwrap_or(to), MouseButton::Left, Modifiers::none());
    vcx.run_until_parked();
}

/// The detail column runs from the list's right edge to the window's.
fn detail_width(vcx: &mut VisualTestContext) -> f32 {
    let window = vcx.update(|window, _| window.viewport_size().width);
    (window - bounds("list-footer", vcx).right()).as_f32()
}

/// At the minimum window width, neither divider can squeeze the detail column below
/// 320 px, and widths restored from a wider window are fitted the same way.
#[gpui::test]
fn the_detail_column_keeps_320_px(cx: &mut TestAppContext) {
    use gpui::size;
    assert_eq!(super::fit_widths([320., 420.], 820., true), [260., 240.]);
    assert_eq!(super::fit_widths([220., 300.], 1100., true), [220., 300.]);
    assert_eq!(super::fit_widths([220., 420.], 820., false), [220., 420.]);

    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    vcx.simulate_resize(size(px(820.), px(720.)));
    frame(&mut vcx);
    assert!(
        detail_width(&mut vcx) >= 319.5,
        "{}",
        detail_width(&mut vcx)
    );
    drag_by("column-handle List", 200., None, &mut vcx);
    frame(&mut vcx);
    assert!(
        detail_width(&mut vcx) >= 319.5,
        "list drag: {}",
        detail_width(&mut vcx)
    );
    drag_by("column-handle Sidebar", 200., None, &mut vcx);
    frame(&mut vcx);
    assert!(
        detail_width(&mut vcx) >= 319.5,
        "sidebar drag: {}",
        detail_width(&mut vcx)
    );
    let [side, list] = main.read_with(&vcx, |m, _| m.widths);
    assert!(side + list <= 820. - 320. + 0.5, "{side} + {list}");

    // Widths saved in a wide window, restored into an 820 px one.
    let window = vcx.cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|cx| MainScreen::new(state.clone(), Some([320., 420.]), window, cx));
        Root::new(view, window, cx)
    });
    let mut narrow = VisualTestContext::from_window(window.into(), &vcx.cx);
    narrow.simulate_resize(size(px(820.), px(720.)));
    frame(&mut narrow);
    assert!(
        detail_width(&mut narrow) >= 319.5,
        "restored: {}",
        detail_width(&mut narrow)
    );
}

/// A divider drag released outside the window still saves the widths.
#[gpui::test]
fn a_drag_released_outside_the_window_saves_the_widths(cx: &mut TestAppContext) {
    use gpui::point;
    let dir = tempfile::tempdir().unwrap();
    let (_, main, mut vcx) = open(true, dir.path(), cx);
    let reported = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = reported.clone();
    let _sub = vcx.update(|_, cx| {
        cx.subscribe(&main, move |_, ev: &super::ColumnsResized, _| {
            sink.borrow_mut().push(ev.0);
        })
    });
    let outside = point(px(-60.), px(-40.));
    drag_by("column-handle Sidebar", 30., Some(outside), &mut vcx);
    let widths = main.read_with(&vcx, |m, _| m.widths);
    assert_eq!(reported.borrow().as_slice(), &[widths]);
    // A plain click elsewhere afterwards saves nothing more.
    let footer = bounds("list-footer", &mut vcx).center();
    vcx.simulate_click(footer, Modifiers::none());
    assert_eq!(reported.borrow().len(), 1);
}

/// Under Reduce Motion the toggle is instant, and the columns still keep their
/// element identity and state (no remount, no replayed fade).
#[gpui::test]
fn columns_keep_their_identity_under_reduce_motion(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    state.update(&mut vcx, |s, cx| s.set_reduce_motion(true, cx));
    frame(&mut vcx);
    let before = ui::probe::take();
    let names = ["detail-probe", "detail-content-probe", "list-probe"];
    let paths: Vec<String> = names
        .iter()
        .map(|n| {
            before
                .iter()
                .rev()
                .find(|s| s.name == *n)
                .expect(n)
                .path
                .clone()
        })
        .collect();
    for _ in 0..2 {
        state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
        vcx.run_until_parked();
        assert!(!has("sidebar-slide", &mut vcx));
        frame(&mut vcx);
        let seen = ui::probe::take();
        assert!(seen.len() >= names.len(), "rendered");
        for s in &seen {
            let ix = names.iter().position(|n| *n == s.name).unwrap();
            assert_eq!(s.path, paths[ix], "{} changed identity", s.name);
            assert!(!s.fresh, "{} remounted", s.name);
        }
    }
}

/// Whether the list is focused and draws its focus ring.
fn list_ring(main: &gpui::Entity<MainScreen>, vcx: &mut VisualTestContext) -> (bool, bool) {
    frame(vcx);
    vcx.update(|window, cx| {
        let focused = main.read(cx).list_focus.is_focused(window);
        (focused, focused && ui::focus_ring_allowed())
    })
}

/// ⌃⌘S neither moves focus nor turns on the list's focus ring: not when the list was
/// focused by a click (the reported outline), and a ring from keyboard focus stays.
#[gpui::test]
fn toggling_keeps_focus_and_the_list_ring_state(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_, main, mut vcx) = open(true, dir.path(), cx);

    // Focused by clicking a row: focused, no ring, before and after both toggles.
    main.read_with(&vcx, |m, _| m.list_state.scroll_to_reveal_item(1));
    vcx.run_until_parked();
    let row = main.read_with(&vcx, |m, _| m.list_state.bounds_for_item(1).unwrap());
    vcx.simulate_click(row.center(), Modifiers::none());
    assert_eq!(list_ring(&main, &mut vcx), (true, false));
    let before = focused(&mut vcx);
    for _ in 0..2 {
        vcx.simulate_keystrokes("ctrl-cmd-s");
        settle(&mut vcx);
        assert_eq!(focused(&mut vcx), before, "focus moved");
        assert_eq!(list_ring(&main, &mut vcx), (true, false), "ring turned on");
    }
    // Other shortcuts do not draw it either.
    vcx.simulate_keystrokes("cmd-d");
    assert_eq!(list_ring(&main, &mut vcx), (true, false));

    // Focused from the keyboard (⌘F, then ⌘1): ring, and a toggle keeps it.
    // (A frame between the keys, as in the app: gpui reports focus changes per frame.)
    vcx.simulate_keystrokes("cmd-f");
    frame(&mut vcx);
    vcx.simulate_keystrokes("cmd-1");
    frame(&mut vcx);
    assert_eq!(list_ring(&main, &mut vcx), (true, true));
    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);
    assert_eq!(list_ring(&main, &mut vcx), (true, true));
    // A click in the list turns it off.
    main.read_with(&vcx, |m, _| m.list_state.scroll_to_reveal_item(1));
    vcx.run_until_parked();
    let row = main.read_with(&vcx, |m, _| m.list_state.bounds_for_item(1).unwrap());
    vcx.simulate_click(row.center(), Modifiers::none());
    assert_eq!(list_ring(&main, &mut vcx), (true, false));
}

/// Focus inside the sidebar moves to the search field when the sidebar collapses (as
/// in Finder), with no list ring.
#[gpui::test]
fn collapsing_moves_sidebar_focus_to_search(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    let all = bounds("nav All Items icon=LayoutList", &mut vcx);
    vcx.simulate_click(all.center(), Modifiers::none());
    assert!(vcx.update(|window, cx| main.read(cx).sidebar_focus.contains_focused(window, cx)));

    vcx.simulate_keystrokes("ctrl-cmd-s");
    settle(&mut vcx);
    assert!(!visible(&state, &vcx));
    assert!(vcx.update(|window, cx| main.read(cx).search_focused(window, cx)));
    assert_eq!(list_ring(&main, &mut vcx), (false, false));
    // Typing goes to the search field.
    vcx.simulate_input("visa");
    assert_eq!(state.read_with(&vcx, |s, _| s.query.clone()), "visa");
}

/// Unlocking with the sidebar collapsed shows the main screen at rest from its first
/// frame: no slide, the search row already clear of the traffic lights.
#[gpui::test]
fn first_frame_after_unlock_is_at_rest_when_collapsed(cx: &mut TestAppContext) {
    use crate::root::VaultRoot;
    use crate::state::Screen;
    let dir = tempfile::tempdir().unwrap();
    let path = {
        let v = vault_sync::SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new(PW.into()),
            vault_core::KdfParams::for_tests(),
            vault_core::Uuid::new_v4(),
            std::sync::Arc::new(vault_sync::NoopHooks),
        )
        .unwrap();
        v.path().to_owned()
    };
    let state = cx.new(|_| AppState::new(vault_core::Uuid::new_v4(), Vec::new(), false));
    cx.update(|cx| {
        gpui_component::init(cx);
        crate::actions::bind_keys(cx);
        crate::actions::register(&state, cx);
    });
    let window = cx.add_window(|window, cx| {
        crate::theme::apply(window, cx);
        let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
        Root::new(view, window, cx)
    });
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    let unlock = |vcx: &mut VisualTestContext| {
        state.update(vcx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
        vcx.run_until_parked();
        vcx.executor().advance_clock(Duration::from_secs(1));
        vcx.run_until_parked();
        assert_eq!(state.read_with(vcx, |s, _| s.screen), Screen::Main);
    };
    state.update(&mut vcx, |s, cx| s.open_vault(path, cx));
    vcx.run_until_parked();
    unlock(&mut vcx);

    state.update(&mut vcx, |s, cx| s.toggle_sidebar(cx));
    settle(&mut vcx);
    state.update(&mut vcx, |s, cx| s.lock(cx));
    vcx.run_until_parked();
    unlock(&mut vcx);
    // The first frames after the remount: at rest, not replaying the collapse.
    for _ in 0..2 {
        assert!(!has("sidebar-slide", &mut vcx), "slide in progress");
        let toggle = bounds("sidebar-toggle Show Sidebar", &mut vcx);
        assert!(
            toggle.left() >= px(ui::COLLAPSED_PAD_X),
            "search row at {:?}",
            toggle.left()
        );
        assert!(bounds("list-search", &mut vcx).left() > toggle.right());
        frame(&mut vcx);
    }
}

/// Whether a quad in the ring colour with a border is painted at `selector`'s bounds.
fn ring_painted(selector: &'static str, vcx: &mut VisualTestContext) -> bool {
    let area = bounds(selector, vcx);
    vcx.update(|window, cx| {
        let ring = gpui_component::ActiveTheme::theme(cx).ring;
        let scaled = area.scale(window.scale_factor());
        let near = |a: gpui::ScaledPixels, b: gpui::ScaledPixels| (a.0 - b.0).abs() < 1.;
        window.painted_quads().iter().any(|q| {
            near(q.bounds.origin.x, scaled.origin.x)
                && near(q.bounds.origin.y, scaled.origin.y)
                && near(q.bounds.size.width, scaled.size.width)
                && q.border_widths.left.0 > 0.
                && q.border_color == ring
        })
    })
}

/// Whether `handle` is focused and may draw its ring, as of a fresh frame.
fn ring_on(handle: &gpui::FocusHandle, vcx: &mut VisualTestContext) -> (bool, bool) {
    frame(vcx);
    vcx.update(|window, _| {
        let focused = handle.is_focused(window);
        (focused, focused && ui::focus_ring_allowed())
    })
}

/// The detail column: clicked into, then the window narrowed and a shortcut pressed,
/// it shows no ring (the reported outline). Focused from the keyboard (⌘2, or Tab on
/// to a value), it does.
#[gpui::test]
fn detail_ring_only_after_keyboard_focus(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, main, mut vcx) = open(true, dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        let id = s.listing.items[1];
        s.select(id, cx);
    });
    vcx.run_until_parked();
    let detail = main.read_with(&vcx, |m, _| m.detail_focus.clone());
    let footer = bounds("detail-footer", &mut vcx).center();
    vcx.simulate_click(footer, Modifiers::none());
    assert_eq!(
        ring_on(&detail, &mut vcx),
        (true, false),
        "click focuses, no ring"
    );
    vcx.simulate_resize(gpui::size(px(860.), px(640.)));
    assert_eq!(ring_on(&detail, &mut vcx), (true, false), "after a resize");
    vcx.simulate_keystrokes("cmd-shift-c");
    assert_eq!(
        ring_on(&detail, &mut vcx),
        (true, false),
        "after a shortcut"
    );
    assert!(
        !ring_painted("detail-column", &mut vcx),
        "ring painted after a shortcut"
    );

    // Keyboard: ⌘1 then ⌘2 moves focus back by key: ring.
    vcx.simulate_keystrokes("cmd-1");
    frame(&mut vcx);
    vcx.simulate_keystrokes("cmd-2");
    assert_eq!(ring_on(&detail, &mut vcx), (true, true), "⌘2");
    assert!(
        ring_painted("detail-column", &mut vcx),
        "ring painted after ⌘2"
    );
    // A click inside clears it again (the footer moved with the resize).
    let footer = bounds("detail-footer", &mut vcx).center();
    vcx.simulate_click(footer, Modifiers::none());
    assert_eq!(ring_on(&detail, &mut vcx), (true, false), "click clears");
    // Tab on to the first value: that value takes focus with a ring.
    vcx.simulate_keystrokes("tab");
    frame(&mut vcx);
    let moved = vcx.update(|window, cx| window.focused(cx));
    assert!(
        moved.is_some() && moved.as_ref() != Some(&detail),
        "Tab moved focus"
    );
    assert!(
        vcx.update(|_, _| ui::focus_ring_allowed()),
        "Tab shows the ring"
    );
}

/// A sidebar row focused by a click shows no ring, even after a key press.
#[gpui::test]
fn sidebar_row_ring_only_after_keyboard_focus(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, mut vcx) = open(true, dir.path(), cx);
    let all = bounds("nav All Items icon=LayoutList", &mut vcx).center();
    vcx.simulate_click(all, Modifiers::none());
    frame(&mut vcx);
    let row = vcx
        .update(|window, cx| window.focused(cx))
        .expect("row focused");
    assert_eq!(ring_on(&row, &mut vcx), (true, false));
    vcx.simulate_keystrokes("cmd-d");
    assert_eq!(ring_on(&row, &mut vcx), (true, false), "after a shortcut");
}

/// Whether any border in the ring colour is painted in the window.
fn any_ring_painted(vcx: &mut VisualTestContext) -> bool {
    frame(vcx);
    vcx.update(|window, cx| {
        let ring = gpui_component::ActiveTheme::theme(cx).ring;
        window
            .painted_quads()
            .iter()
            .any(|q| q.border_widths.left.0 > 0. && q.border_color == ring)
    })
}

/// A window with one focusable element the test can remove.
struct FocusTarget(Option<gpui::FocusHandle>);

impl gpui::Render for FocusTarget {
    fn render(
        &mut self,
        window: &mut gpui::Window,
        cx: &mut gpui::Context<Self>,
    ) -> impl gpui::IntoElement {
        use gpui::{InteractiveElement as _, ParentElement as _, Styled as _};
        ui::update_focus_ring(window, cx);
        gpui::div().size_full().children(
            self.0
                .as_ref()
                .map(|h| gpui::div().id("target").track_focus(h).size(px(20.))),
        )
    }
}

/// The ring map holds focus weakly: a keyboard-focused element that is removed leaves
/// the window with no focus and no ring (a strong handle kept it "focused").
#[gpui::test]
fn removed_keyboard_focus_leaves_no_stale_focus_or_ring(cx: &mut TestAppContext) {
    let mut weak = None;
    let mut view = None;
    let window = cx.add_window(|_, cx| {
        let handle = cx.focus_handle();
        weak = Some(handle.downgrade());
        let v = FocusTarget(Some(handle));
        view = Some(cx.entity());
        v
    });
    let view = view.unwrap();
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    vcx.simulate_keystrokes("a");
    let handle = weak.as_ref().unwrap().upgrade().unwrap();
    vcx.update(|window, cx| window.focus(&handle, cx));
    drop(handle);
    frame(&mut vcx);
    assert!(vcx.update(|window, cx| window.focused(cx).is_some()));
    assert!(ui::focus_ring_allowed(), "keyboard focus shows the ring");

    view.update(&mut vcx, |v, cx| {
        v.0 = None;
        cx.notify();
    });
    frame(&mut vcx);
    frame(&mut vcx);
    assert!(
        weak.unwrap().upgrade().is_none(),
        "the handle is not kept alive"
    );
    assert!(
        vcx.update(|window, cx| window.focused(cx).is_none()),
        "stale focus"
    );
    assert!(!ui::focus_ring_allowed(), "stale ring");
}

/// In an item window, Tab draws the ring and a click clears it; closing the window
/// removes its ring entry.
#[gpui::test]
fn item_window_ring_and_its_entry_on_close(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    let board = crate::clipboard::fake::FakePasteboard::default();
    state.update(&mut vcx, |s, _| s.set_pasteboard(Box::new(board)));
    let id = state.read_with(&vcx, |s, _| {
        s.listing
            .items
            .iter()
            .copied()
            .find(|id| s.unlocked_vault().unwrap().get(*id).unwrap().title == "GitHub")
            .unwrap()
    });
    let handle = vcx
        .update(|_, cx| crate::screens::open_item_window(state.clone(), id, cx))
        .unwrap();
    let mut item = VisualTestContext::from_window(handle, &vcx.cx);
    frame(&mut item);
    let window_id = handle.window_id();
    assert!(ui::focus_ring_windows().contains(&window_id));
    assert!(!any_ring_painted(&mut item), "no ring before any focus");

    // A click focuses the first value (Tab needs a focus to move from): no ring.
    let value = item.debug_bounds("field-value 0").expect("value").center();
    item.simulate_click(value, Modifiers::none());
    let clicked = item.update(|window, cx| window.focused(cx));
    assert!(clicked.is_some());
    assert!(!any_ring_painted(&mut item), "a click shows no ring");
    // Tab moves on (past the value's Copy button, a gpui-component Button with its
    // own focus line) to the next value area: ring.
    let mut ringed = false;
    for _ in 0..4 {
        item.simulate_keystrokes("tab");
        let tabbed = item.update(|window, cx| window.focused(cx));
        assert!(tabbed.is_some() && tabbed != clicked, "Tab moved focus");
        assert!(ui::focus_ring_allowed(), "keyboard focus may draw its ring");
        if any_ring_painted(&mut item) {
            ringed = true;
            break;
        }
    }
    assert!(ringed, "Tab shows the ring on the next value");
    // A click clears it.
    item.simulate_click(value, Modifiers::none());
    assert!(!any_ring_painted(&mut item), "a click clears it");

    item.update(|window, _| window.remove_window());
    vcx.run_until_parked();
    assert!(
        !ui::focus_ring_windows().contains(&window_id),
        "entry left behind"
    );
}
