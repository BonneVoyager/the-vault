//! Sync banners at the top of the detail column (specs/05-ui.md §3, specs/03-sync.md §3):
//! unreadable file on disk, waiting for iCloud, and the inline "re-keyed on another
//! device" password prompt. They sit in the title-bar band, above the item or editor.

use gpui::{
    AnyElement, App, Entity, IntoElement, ParentElement as _, Styled as _, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::alert::Alert;
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::InputState;
use gpui_component::{ActiveTheme as _, Sizable as _};

use crate::state::{AppState, Busy};
use crate::ui;

pub const CORRUPT: &str =
    "The vault file on disk is unreadable; your in-memory copy will be re-saved.";
pub const WAITING_FOR_CLOUD: &str = "Waiting for iCloud to download the vault\u{2026}";
pub const KEY_MISMATCH: &str =
    "This vault was re-keyed on another device. Enter the master password to continue.";

/// All active banners, or `None` when there are none.
pub fn render(
    s: &AppState,
    state: &Entity<AppState>,
    key_input: &Entity<InputState>,
    cx: &App,
) -> Option<AnyElement> {
    if !s.sync.has_banner() {
        return None;
    }
    let theme = cx.theme();
    let busy = s.busy == Some(Busy::Reverifying);
    let key_prompt = s.sync.key_mismatch.then(|| {
        let (submit_state, submit_input) = (state.clone(), key_input.clone());
        ui::v_flex()
            .gap(px(8.))
            .px(px(12.))
            .py(px(10.))
            .rounded(theme.radius)
            .bg(theme.warning.opacity(0.10))
            .border_1()
            .border_color(theme.warning.opacity(0.40))
            .child(div().text_sm().child(KEY_MISMATCH))
            .child(
                ui::h_flex()
                    .gap(px(8.))
                    .child(
                        div()
                            .flex_1()
                            .child(ui::input(key_input).small().mask_toggle()),
                    )
                    .child(
                        Button::new("key-mismatch-submit")
                            .primary()
                            .small()
                            .label("Continue")
                            .loading(busy)
                            .on_click(move |_, window, cx| {
                                submit_key(&submit_state, &submit_input, window, cx);
                            }),
                    ),
            )
            .when_some(s.sync.key_mismatch_error.clone(), |col, error| {
                col.child(div().text_sm().text_color(theme.danger).child(error))
            })
    });
    Some(
        ui::v_flex()
            .pt(px(ui::TITLEBAR_HEIGHT))
            .px(px(28.))
            .gap(px(8.))
            .when(s.sync.corrupt, |col| {
                col.child(Alert::error("banner-corrupt", CORRUPT).small())
            })
            .when(s.sync.waiting_for_cloud, |col| {
                col.child(Alert::warning("banner-cloud", WAITING_FOR_CLOUD).small())
            })
            .children(key_prompt)
            .into_any_element(),
    )
}

/// Enter in the prompt or "Continue": hand the password to the state and clear the field.
pub fn submit_key(
    state: &Entity<AppState>,
    input: &Entity<InputState>,
    window: &mut gpui::Window,
    cx: &mut App,
) {
    if ui::input_is_empty(input, cx) {
        return;
    }
    let password = ui::input_secret(input, cx);
    ui::clear_input(input, window, cx);
    state.update(cx, |s, cx| s.resolve_key_mismatch(password, cx));
}
