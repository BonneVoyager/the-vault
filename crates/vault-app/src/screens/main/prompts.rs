//! Inline confirms in the detail header (specs/05-ui.md §2.3): "Discard changes?" and
//! "Delete '<title>'?". Banners, not modals: the rest of the window stays usable.

use gpui::{
    AnyElement, App, Entity, IntoElement, ParentElement as _, SharedString, Styled as _, div, px,
};
use gpui_component::ActiveTheme as _;
use gpui_component::Sizable as _;
use gpui_component::button::{Button, ButtonVariants as _};

use crate::state::AppState;
use crate::ui;

/// A tinted strip with a message and two buttons.
fn banner(
    message: impl Into<SharedString>,
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
        .child(div().flex_1().min_w_0().text_sm().child(message.into()))
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
        Button::new("discard-confirm")
            .danger()
            .small()
            .label("Discard")
            .on_click(move |_, _, cx| drop.update(cx, |s, cx| s.discard_changes(cx))),
        Button::new("discard-keep")
            .ghost()
            .small()
            .label("Keep editing")
            .on_click(move |_, _, cx| keep.update(cx, |s, cx| s.keep_editing(cx))),
        cx,
    ))
}

/// The delete confirm for the selected item.
pub fn delete(s: &AppState, state: &Entity<AppState>, cx: &App) -> Option<AnyElement> {
    let id = s.delete_confirm?;
    let item = s.selected_item().filter(|i| i.id == id)?;
    let title = if item.title.trim().is_empty() {
        "this item".to_owned()
    } else {
        format!("\u{2018}{}\u{2019}", crate::text::truncate(&item.title, 40))
    };
    let (yes, no) = (state.clone(), state.clone());
    Some(banner(
        format!("Delete {title}?"),
        Button::new("delete-confirm")
            .danger()
            .small()
            .label("Delete")
            .on_click(move |_, _, cx| yes.update(cx, |s, cx| s.confirm_delete(cx))),
        Button::new("delete-cancel")
            .ghost()
            .small()
            .label("Cancel")
            .on_click(move |_, _, cx| no.update(cx, |s, cx| s.cancel_delete(cx))),
        cx,
    ))
}
