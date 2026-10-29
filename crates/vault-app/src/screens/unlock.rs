//! Unlock (specs/05-ui.md §2.2), with Touch ID when enrolled and the policy allows
//! (specs/04-macos.md §2). Touch ID starts by itself when the screen appears after the
//! vault was opened, and on the next window activation after a lock.

use std::f32::consts::PI;
use std::time::Duration;

use gpui::{
    Animation, AnimationExt as _, AnyElement, Context, Entity, FontWeight, IntoElement,
    ParentElement as _, Render, Styled as _, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;

use crate::state::{AppState, Busy, ChooseIntent, Screen, TouchDenied};
use crate::ui;

const SHAKE: Duration = Duration::from_millis(400);
/// Peak horizontal displacement of the shake.
const SHAKE_PX: f32 = 10.;

pub struct UnlockScreen {
    state: Entity<AppState>,
    password: Entity<InputState>,
    _subscriptions: Vec<Subscription>,
}

impl UnlockScreen {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let password = ui::password_input("Master password", window, cx);
        let subscriptions = vec![
            cx.observe(&state, |_, _, cx| cx.notify()),
            cx.observe_window_activation(window, |this, window, cx| {
                let on_screen = this.state.read(cx).screen == Screen::Unlock;
                if on_screen && window.is_window_active() {
                    this.state.update(cx, |s, cx| s.auto_touch_unlock(true, cx));
                }
            }),
            cx.subscribe_in(&password, window, |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit(window, cx);
                }
            }),
        ];
        Self {
            state,
            password,
            _subscriptions: subscriptions,
        }
    }

    /// Called by the root view whenever the screen becomes visible.
    pub fn appear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        ui::clear_input(&self.password, window, cx);
        ui::focus_input(&self.password, window, cx);
        self.state
            .update(cx, |s, cx| s.auto_touch_unlock(false, cx));
    }

    /// Called by the root view when the screen is replaced (unlocked, ⌘O, ...).
    pub fn disappear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        ui::clear_input(&self.password, window, cx);
    }

    fn submit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.read(cx).busy.is_some() || ui::input_is_empty(&self.password, cx) {
            return;
        }
        let password = ui::input_secret(&self.password, cx);
        ui::clear_input(&self.password, window, cx);
        self.state.update(cx, |s, cx| s.unlock(password, cx));
    }
}

/// Damped sine: three swings that settle back to 0 at `t = 1`.
fn shake_offset(t: f32) -> f32 {
    (t * PI * 6.).sin() * SHAKE_PX * (1. - t)
}

impl Render for UnlockScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let state = self.state.read(cx);
        let name = state.vault_name();
        let path = state
            .vault_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let busy = state.busy == Some(Busy::Unlocking);
        let touching = state.busy == Some(Busy::TouchUnlocking);
        let touch = state.touch_policy();
        let touch_hint = touch.err().and_then(TouchDenied::hint);
        let error = state.error.clone();
        let failures = state.unlock_failures;
        let reduce_motion = state.reduce_motion;
        let theme = cx.theme();

        let mut card = ui::card(cx)
            .w(px(360.))
            .items_center()
            .child(
                Icon::new(IconName::Lock)
                    .large()
                    .text_color(theme.muted_foreground),
            )
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(name),
            )
            .child(
                div()
                    .w_full()
                    .text_xs()
                    .text_center()
                    .text_color(theme.muted_foreground)
                    .overflow_hidden()
                    .text_ellipsis()
                    .child(path),
            )
            .child(
                div()
                    .w_full()
                    .child(ui::input(&self.password).disabled(busy || touching)),
            );
        if let Some(hint) = touch_hint {
            card = card.child(
                div()
                    .w_full()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(hint),
            );
        }
        if let Some(error) = error {
            card = card.child(
                div()
                    .w_full()
                    .text_sm()
                    .text_color(theme.danger)
                    .child(error),
            );
        }
        card = card
            .child(
                div().w_full().child(
                    Button::new("unlock")
                        .primary()
                        .w_full()
                        .label("Unlock")
                        .loading(busy)
                        .disabled(busy || touching)
                        .on_click(cx.listener(|this, _, window, cx| this.submit(window, cx))),
                ),
            )
            .when(touch.is_ok(), |card| {
                card.child(
                    div().w_full().child(
                        Button::new("touch-id")
                            .w_full()
                            .icon(Icon::new(IconName::FingerprintPattern))
                            .label("Unlock with Touch ID")
                            .loading(touching)
                            .disabled(busy || touching)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.state.update(cx, |s, cx| s.touch_unlock(cx));
                            })),
                    ),
                )
            })
            .child(
                Button::new("switch")
                    .ghost()
                    .small()
                    .label("Open another vault…  ⌘O")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.state
                            .update(cx, |s, cx| s.switch_vault(ChooseIntent::Home, cx));
                    })),
            );

        // Each wrong password gets a fresh element id, which restarts the animation.
        let card: AnyElement = if failures == 0 || reduce_motion {
            card.into_any_element()
        } else {
            card.relative()
                .with_animation(("shake", failures), Animation::new(SHAKE), |card, t| {
                    card.left(px(shake_offset(t)))
                })
                .into_any_element()
        };
        ui::centered(cx).child(card)
    }
}
