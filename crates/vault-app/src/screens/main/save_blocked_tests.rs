//! Headless render tests for the save-blocked strip (owner decision 2026-11-07): a red
//! strip under the title band of the list and detail columns while saves are refused
//! for a lasting reason, gone after the next successful save.

use gpui::{Bounds, Pixels, TestAppContext, VisualTestContext, px, size};
use vault_sync::{SaveBlocked, SyncError, SyncEvent};

use super::save_blocked::SHOW_TRASH;
use super::tests::open;
use crate::state::{AppState, Filter};
use crate::ui;

const BANNER: &str = "save-blocked-banner";
const LINK: &str = "save-blocked-show-trash";

fn frame(vcx: &mut VisualTestContext) {
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
}

fn bounds(key: &'static str, vcx: &mut VisualTestContext) -> Bounds<Pixels> {
    vcx.debug_bounds(key)
        .unwrap_or_else(|| panic!("{key} not rendered"))
}

fn near(a: Pixels, b: Pixels) -> bool {
    (a.as_f32() - b.as_f32()).abs() < 0.5
}

/// An edit, then the autosave refused for size (as in `state/sync.rs`).
fn refuse_for_size(state: &gpui::Entity<AppState>, vcx: &mut VisualTestContext) {
    let cap = vault_sync::MAX_VAULT_FILE_SIZE;
    state.update(vcx, |s, cx| {
        s.toggle_favorite(cx);
        s.finish_autosave_for_test(
            Err(SyncError::VaultTooLarge {
                bytes: cap + 5 * 1024 * 1024 + 1,
                cap,
            }),
            cx,
        );
    });
    frame(vcx);
}

#[gpui::test]
fn too_large_strip_pushes_both_columns_down_until_a_save_works(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    // Narrow enough that the message wraps: both columns must still match its height.
    vcx.simulate_resize(size(px(900.), px(640.)));
    frame(&mut vcx);
    assert!(vcx.debug_bounds(BANNER).is_none(), "no strip normally");
    let list_top = bounds("item-list", &mut vcx).top();
    let detail_top = bounds("detail-column", &mut vcx).top();
    let header_top = bounds("detail-header", &mut vcx).top();

    refuse_for_size(&state, &mut vcx);
    let expected = "The vault is too large to save (70 MiB, limit 64 MiB). Remove large notes \
                    or field values (also from Recently Deleted); until then, changes are not \
                    saved.";
    state.read_with(&vcx, |s, _| {
        let notice = s.save_blocked().expect("strip state");
        assert_eq!(notice.message.as_ref(), expected);
        assert!(notice.offers_trash);
    });
    let banner = bounds(BANNER, &mut vcx);
    let message = bounds("save-blocked-message", &mut vcx);
    assert!(banner.contains(&message.center()));
    assert!(
        message.size.height > px(20.),
        "wraps at 900 px: {message:?}"
    );
    // Directly under the title band, from the list's left edge to the window's right.
    assert!(near(banner.top(), px(ui::TOP_BAND_HEIGHT)), "{banner:?}");
    let list_x = bounds("list-footer", &mut vcx).left();
    assert!(near(banner.left(), list_x), "{banner:?} vs {list_x:?}");
    assert!(near(banner.right(), px(900.)), "{banner:?}");
    // The search row stays in the band; the list rows and the detail start below.
    assert!(bounds("list-search", &mut vcx).bottom() <= banner.top());
    let list = bounds("item-list", &mut vcx);
    let detail = bounds("detail-column", &mut vcx);
    assert!(near(list.top(), banner.bottom()), "{list:?} vs {banner:?}");
    assert!(
        near(detail.top(), banner.bottom()),
        "{detail:?} vs {banner:?}"
    );
    assert!(list.top() > list_top && detail.top() > detail_top);
    assert!(bounds("detail-header", &mut vcx).top() > banner.bottom());
    // The sidebar keeps its full height.
    assert!(near(bounds("sidebar-column", &mut vcx).top(), px(0.)));

    // The link opens Recently Deleted; the strip stays.
    let link = bounds(LINK, &mut vcx);
    assert!(banner.contains(&link.center()));
    assert_eq!(SHOW_TRASH, "Show Recently Deleted");
    vcx.simulate_click(link.center(), gpui::Modifiers::none());
    frame(&mut vcx);
    assert_eq!(
        state.read_with(&vcx, |s, _| s.filter.clone()),
        Filter::RecentlyDeleted
    );
    assert!(vcx.debug_bounds(BANNER).is_some());

    // Collapsed sidebar: the strip spans the window.
    state.update(&mut vcx, |s, cx| {
        s.reduce_motion = true;
        s.toggle_sidebar(cx);
    });
    frame(&mut vcx);
    frame(&mut vcx);
    let banner = bounds(BANNER, &mut vcx);
    assert!(near(banner.left(), px(0.)), "{banner:?}");
    // Collapsed, the filter heading leads the list column under the strip.
    let heading = bounds("list-filter-heading", &mut vcx);
    assert!(
        near(heading.top(), banner.bottom()),
        "{heading:?} vs {banner:?}"
    );
    assert!(near(
        bounds("detail-column", &mut vcx).top(),
        banner.bottom()
    ));
    state.update(&mut vcx, |s, cx| {
        s.toggle_sidebar(cx);
        s.set_filter(Filter::default(), cx);
    });
    frame(&mut vcx);
    frame(&mut vcx);

    // A save that works (the vault shrank) removes it and the columns move back.
    state.update(&mut vcx, |s, cx| {
        let result = s.vault.as_mut().unwrap().save();
        s.finish_autosave_for_test(result, cx);
        assert!(s.save_blocked().is_none());
    });
    frame(&mut vcx);
    assert!(vcx.debug_bounds(BANNER).is_none());
    assert!(vcx.debug_bounds(LINK).is_none());
    assert!(near(bounds("item-list", &mut vcx).top(), list_top));
    assert!(near(bounds("detail-column", &mut vcx).top(), detail_top));
    assert!(near(bounds("detail-header", &mut vcx).top(), header_top));
}

/// At the largest text size the search row outgrows the title band: the strip starts
/// under the row, not over it, and both columns still start under the strip.
#[gpui::test]
fn strip_follows_the_search_row_at_the_largest_text_size(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    let largest = *crate::state::TextSize::ALL.last().unwrap();
    state.update(&mut vcx, |s, cx| {
        s.update_settings(cx, |st| st.text_size = largest)
    });
    frame(&mut vcx);
    let search = bounds("list-search", &mut vcx);
    assert!(
        search.bottom() + px(ui::SEARCH_TOP) > px(ui::TOP_BAND_HEIGHT + 1.),
        "the row really is taller than the band: {search:?}"
    );
    refuse_for_size(&state, &mut vcx);
    let banner = bounds(BANNER, &mut vcx);
    assert!(search.bottom() <= banner.top(), "{search:?} vs {banner:?}");
    assert!(near(banner.top(), search.bottom() + px(ui::SEARCH_TOP)));
    assert!(near(bounds("item-list", &mut vcx).top(), banner.bottom()));
    assert!(near(
        bounds("detail-column", &mut vcx).top(),
        banner.bottom()
    ));
    // The row itself did not move.
    assert_eq!(bounds("list-search", &mut vcx), search);
}

/// A busy save lock is transient: toasted, never on the strip.
#[gpui::test]
fn busy_lock_failure_shows_no_strip(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.toggle_favorite(cx);
        s.finish_autosave_for_test(Err(SyncError::SaveLockTimeout(dir.path().into())), cx);
        assert!(s.sync.save_failing);
        assert!(s.save_blocked().is_none());
    });
    frame(&mut vcx);
    assert!(vcx.debug_bounds(BANNER).is_none());
}

/// A refused save (`SaveBlocked`) persists in the status line too: same strip with its
/// status-line text, but no Recently Deleted link (deleting does not help).
#[gpui::test]
fn save_blocked_event_shows_the_strip_without_the_link(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = open(true, dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.handle_sync_event(SyncEvent::SaveBlocked(SaveBlocked::NewerVersion(99)), cx);
    });
    frame(&mut vcx);
    state.read_with(&vcx, |s, _| {
        let notice = s.save_blocked().unwrap();
        assert_eq!(
            notice.message.as_ref(),
            "Not saving: a newer version of Vault wrote this vault. Update Vault to keep editing."
        );
        assert!(!notice.offers_trash);
    });
    assert!(vcx.debug_bounds(BANNER).is_some());
    assert!(vcx.debug_bounds(LINK).is_none());
}
