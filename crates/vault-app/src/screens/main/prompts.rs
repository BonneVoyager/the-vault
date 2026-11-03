//! Inline confirms in the detail header (specs/05-ui.md §2.3): "Discard changes?" and
//! "Delete '<title>'?". Banners, not modals: the rest of the window stays usable.

use gpui::{
    AnyElement, App, Entity, InteractiveElement as _, IntoElement, ParentElement as _,
    SharedString, Styled as _, div, px,
};
use gpui_component::ActiveTheme as _;
use gpui_component::Sizable as _;
use gpui_component::button::{Button, ButtonVariants as _};

use crate::state::{AppState, DELETE_RECOVERABLE, PURGE_CONFIRM};
use crate::ui::{self, Clickable as _};

/// A tinted strip with a message and two buttons.
fn banner(
    message: impl Into<SharedString>,
    detail: Option<&'static str>,
    confirm: Button,
    cancel: Button,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    ui::h_flex()
        .gap(px(8.))
        .px(px(12.))
        .py(px(8.))
        .rounded(theme.radius)
        .bg(theme.danger.opacity(0.10))
        .border_1()
        .border_color(theme.danger.opacity(0.35))
        .child(
            ui::v_flex()
                .flex_1()
                .min_w_0()
                .text_sm()
                .child({
                    let message: SharedString = message.into();
                    let key = message.clone();
                    // Tests find the confirm's text by this key (no-op outside tests).
                    div()
                        .debug_selector(move || format!("confirm-text {key}"))
                        .child(message)
                })
                .children(detail.map(|d| {
                    div()
                        .debug_selector(move || format!("confirm-detail {d}"))
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(d)
                })),
        )
        .child(cancel)
        .child(confirm)
        .into_any_element()
}

/// The unsaved-changes prompt, while a navigation waits behind it.
pub fn discard(s: &AppState, state: &Entity<AppState>, cx: &App) -> Option<AnyElement> {
    s.discard_prompt.as_ref()?;
    let (keep, drop) = (state.clone(), state.clone());
    Some(banner(
        "Discard changes?",
        None,
        Button::new("discard-confirm")
            .danger()
            .small()
            .label("Discard")
            .clickable()
            .on_click(move |_, _, cx| drop.update(cx, |s, cx| s.discard_changes(cx))),
        Button::new("discard-keep")
            .ghost()
            .small()
            .label("Keep editing")
            .clickable()
            .on_click(move |_, _, cx| keep.update(cx, |s, cx| s.keep_editing(cx))),
        cx,
    ))
}

/// The delete confirm for the selected item.
pub fn delete(s: &AppState, state: &Entity<AppState>, cx: &App) -> Option<AnyElement> {
    let id = s.delete_confirm?;
    let item = s.viewed_item().filter(|i| i.id == id)?;
    let title = if item.title.trim().is_empty() {
        "this item".to_owned()
    } else {
        format!("\u{2018}{}\u{2019}", crate::text::truncate(&item.title, 40))
    };
    // A trashed item is deleted for good; a live one goes to Recently Deleted.
    let (message, detail) = if item.is_deleted() {
        (PURGE_CONFIRM.to_owned(), None)
    } else {
        (format!("Delete {title}?"), Some(DELETE_RECOVERABLE))
    };
    let (yes, no) = (state.clone(), state.clone());
    Some(banner(
        message,
        detail,
        Button::new("delete-confirm")
            .debug_selector(|| "delete-confirm".into())
            .danger()
            .small()
            .label("Delete")
            .clickable()
            .on_click(move |_, _, cx| yes.update(cx, |s, cx| s.confirm_delete(cx))),
        Button::new("delete-cancel")
            .ghost()
            .small()
            .label("Cancel")
            .clickable()
            .on_click(move |_, _, cx| no.update(cx, |s, cx| s.cancel_delete(cx))),
        cx,
    ))
}
