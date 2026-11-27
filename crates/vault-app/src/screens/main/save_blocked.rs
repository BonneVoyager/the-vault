//! The save-blocked strip (owner decision 2026-11-07): a red full-width strip under the
//! title-bar band of the list and detail columns while saves are refused for a reason
//! that persists until a save succeeds (vault too large, `SaveBlocked`). No close button
//! and no motion: it appears and disappears with the state.
//!
//! The strip spans two columns that lay out independently, so their content is pushed
//! down by invisible copies of the strip laid out at the same width (same wrapping, same
//! height): one in the list column under its search row, one in the detail column under
//! the band. The visible strip is the detail column's last child, so it paints and takes
//! clicks above both columns and their divider.

use gpui::{
    App, Entity, InteractiveElement as _, IntoElement, ParentElement as _, Styled as _, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::ActiveTheme as _;
use gpui_component::Sizable as _;
use gpui_component::button::{Button, ButtonVariants as _};

use crate::state::{AppState, Filter, SaveBlockedNotice};
use crate::ui::{self, Clickable as _};

/// The trailing link on the too-large strip.
pub const SHOW_TRASH: &str = "Show Recently Deleted";
/// The trailing action on the not-a-folder strip (L-05).
pub const REPAIR: &str = "Repair";

/// Text size of the strip, before the text-size preference scales it.
const TEXT_SIZE: f32 = 13.;

/// A trailing link-style action on the strip; the spacer copy gets no selector.
fn action(
    id: &'static str,
    label: &'static str,
    spacer: bool,
    state: &Entity<AppState>,
    run: fn(&mut AppState, &mut gpui::Context<AppState>),
) -> gpui::Div {
    let state = state.clone();
    let button = Button::new(id)
        .link()
        .small()
        .label(label)
        .when(!spacer, |b| b.debug_selector(move || id.into()))
        .clickable()
        .on_click(move |_, _, cx| state.update(cx, run));
    div().flex_none().child(button)
}

/// The strip itself; `spacer` builds an invisible copy that only takes up its room.
fn strip(
    notice: &SaveBlockedNotice,
    spacer: bool,
    state: &Entity<AppState>,
    cx: &App,
) -> gpui::Div {
    let theme = cx.theme();
    let trash = notice.offers_trash.then(|| {
        action(
            "save-blocked-show-trash",
            SHOW_TRASH,
            spacer,
            state,
            |s, cx| s.set_filter(Filter::RecentlyDeleted, cx),
        )
    });
    let repair = notice.offers_repair.then(|| {
        action("save-blocked-repair", REPAIR, spacer, state, |s, cx| {
            s.repair_vault_package(cx)
        })
    });
    ui::h_flex()
        .flex_none()
        .items_center()
        .gap(px(8.))
        .px(px(ui::COLUMN_PAD_X))
        .py(px(6.))
        .text_size(crate::theme::scaled(TEXT_SIZE, cx))
        // The danger tint other danger cards use, made opaque over the window colour so
        // the column divider beneath does not show through.
        .bg(theme.background.blend(theme.danger.opacity(0.10)))
        .border_b_1()
        .border_color(theme.background.blend(theme.danger.opacity(0.35)))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_color(theme.danger)
                .when(!spacer, |d| {
                    d.debug_selector(|| "save-blocked-message".into())
                })
                .child(notice.message.clone()),
        )
        .children(trash)
        .children(repair)
        .when(spacer, |el| el.invisible())
}

/// The visible strip: absolutely placed at the top of the detail slot, reaching left
/// over the list column (`list_width`).
pub(super) fn overlay(
    s: &AppState,
    state: &Entity<AppState>,
    list_width: f32,
    cx: &App,
) -> Option<gpui::AnyElement> {
    let notice = s.save_blocked()?;
    Some(
        div()
            .id("save-blocked-banner")
            .debug_selector(|| "save-blocked-banner".into())
            .absolute()
            .top(super::header_height(cx))
            .left(px(-list_width))
            .right_0()
            .child(strip(notice, false, state, cx))
            .into_any_element(),
    )
}

/// Room for the strip in a column: an invisible copy `width` wide, or (`None`) as wide
/// as the column plus `reach_left`.
pub(super) fn spacer(
    s: &AppState,
    state: &Entity<AppState>,
    id: &'static str,
    width: Option<f32>,
    reach_left: f32,
    cx: &App,
) -> Option<gpui::AnyElement> {
    let notice = s.save_blocked()?;
    Some(
        div()
            .id(id)
            .flex_none()
            .map(|el| match width {
                Some(w) => el.w(px(w)),
                None => el.ml(px(-reach_left)),
            })
            .child(strip(notice, true, state, cx))
            .into_any_element(),
    )
}
