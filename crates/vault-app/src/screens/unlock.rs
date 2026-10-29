//! Unlock (specs/05-ui.md §2.2), with Touch ID when enrolled and the policy allows
//! (specs/04-macos.md §2). Touch ID starts by itself when the screen appears after the
//! vault was opened, and on the next window activation after a lock.
//!
//! While a password or Touch ID unlock is being verified the controls are hidden (kept
//! in the layout so the card does not change size) under a spinner and "Unlocking…".

use std::f32::consts::PI;
use std::time::Duration;

use gpui::{
    Animation, AnimationExt as _, AnyElement, Context, Entity, FontWeight, InteractiveElement as _,
    IntoElement, ParentElement as _, Render, StatefulInteractiveElement as _, Styled as _,
    Subscription, Window, div, img, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::spinner::Spinner;
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;

/// Side of the app icon on the unlock card, in points (the raster is 2x this).
const APP_ICON_SIZE: f32 = 128.;

use crate::state::{AppState, Busy, ChooseIntent, Screen, TouchDenied};
use crate::ui::{self, Clickable as _};

const SHAKE: Duration = Duration::from_millis(400);
/// Peak horizontal displacement of the shake.
const SHAKE_PX: f32 = 10.;

pub struct UnlockScreen {
    state: Entity<AppState>,
    password: Entity<InputState>,
    /// Whether the last state notification saw an unlock in flight.
    was_unlocking: bool,
    _subscriptions: Vec<Subscription>,
}

impl UnlockScreen {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let password = ui::password_input("Master password", window, cx);
        let subscriptions = vec![
            cx.observe_in(&state, window, |this, state, window, cx| {
                let s = state.read(cx);
                let unlocking = is_unlocking(s.busy);
                // A failed unlock brings the field back: put the cursor in it again.
                if this.was_unlocking && !unlocking && s.screen == Screen::Unlock {
                    ui::focus_input(&this.password, window, cx);
                }
                this.was_unlocking = unlocking;
                cx.notify();
            }),
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
            was_unlocking: false,
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

/// A password or Touch ID unlock is being verified.
fn is_unlocking(busy: Option<Busy>) -> bool {
    matches!(busy, Some(Busy::Unlocking | Busy::TouchUnlocking))
}

/// Spinner and "Unlocking…", centred over the hidden controls.
fn unlocking_overlay(cx: &gpui::App) -> impl IntoElement {
    ui::v_flex()
        .absolute()
        .inset_0()
        .items_center()
        .justify_center()
        .gap(px(10.))
        .id("unlocking")
        .debug_selector(|| "unlocking".into())
        .aria_label("Unlocking")
        // Static glyph under Reduce Motion: `Spinner` follows gpui's flag, which
        // `AppState::set_reduce_motion` keeps in step.
        .child(Spinner::new().large().color(cx.theme().muted_foreground))
        .child(
            div()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child("Unlocking…"),
        )
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
        let unlocking = is_unlocking(state.busy);
        let touch = state.touch_policy();
        let touch_hint = touch.err().and_then(TouchDenied::hint);
        let error = state.error.clone();
        let failures = state.unlock_failures;
        let reduce_motion = state.reduce_motion;
        let theme = cx.theme();

        let mut controls = ui::v_flex().w_full().gap(px(14.)).child(
            div()
                .w_full()
                .debug_selector(|| "unlock-password".into())
                .child(ui::input(&self.password).disabled(unlocking)),
        );
        if let Some(hint) = touch_hint {
            controls = controls.child(
                div()
                    .w_full()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(hint),
            );
        }
        if let Some(error) = error {
            controls = controls.child(
                div()
                    .w_full()
                    .text_sm()
                    .text_color(theme.danger)
                    .child(error),
            );
        }
        controls = controls
            .child(
                div().w_full().child(
                    Button::new("unlock")
                        .primary()
                        .w_full()
                        .label("Unlock")
                        .disabled(unlocking)
                        .clickable_when(!unlocking)
                        .on_click(cx.listener(|this, _, window, cx| this.submit(window, cx))),
                ),
            )
            .when(touch.is_ok(), |controls| {
                controls.child(
                    div().w_full().child(
                        Button::new("touch-id")
                            .w_full()
                            .icon(Icon::new(IconName::FingerprintPattern))
                            .label("Unlock with Touch ID")
                            .disabled(unlocking)
                            .clickable_when(!unlocking)
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
                    .disabled(unlocking)
                    .clickable_when(!unlocking)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.state
                            .update(cx, |s, cx| s.switch_vault(ChooseIntent::Home, cx));
                    })),
            )
            // Hidden, not removed: the card keeps its size and nothing jumps. A hidden
            // div paints none of its children, so the field takes no clicks or keys.
            .when(unlocking, |controls| controls.invisible());

        let card = ui::card(cx)
            .w(px(360.))
            .items_center()
            .debug_selector(|| "unlock-card".into())
            // The app icon (its PNG already has the macOS squircle and shadow). The
            // fixed box keeps the card size even before the image has decoded.
            .child(
                div()
                    .size(px(APP_ICON_SIZE))
                    .flex_shrink_0()
                    .debug_selector(|| "unlock-icon".into())
                    .child(img(crate::assets::APP_ICON).size_full()),
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
                    .relative()
                    .w_full()
                    .child(controls)
                    .when(unlocking, |area| area.child(unlocking_overlay(cx))),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gpui::{AppContext as _, Focusable as _, TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::{KdfParams, SecretString, Uuid};
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;
    use crate::actions;

    /// The unlock screen on its own window, with a fresh vault opened (locked).
    fn open(
        dir: &std::path::Path,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, Entity<UnlockScreen>, VisualTestContext) {
        let path = dir.join("t.vault");
        drop(
            SyncedVault::create(
                &path,
                &SecretString::new("pw".into()),
                KdfParams::for_tests(),
                Uuid::new_v4(),
                Arc::new(NoopHooks),
            )
            .unwrap(),
        );
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        state.update(cx, |s, cx| s.open_vault(path, cx));
        cx.run_until_parked();
        let mut screen = None;
        let window = cx.add_window(|window, cx| {
            crate::theme::apply(window, cx);
            let view = cx.new(|cx| UnlockScreen::new(state.clone(), window, cx));
            screen = Some(view.clone());
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        let screen = screen.unwrap();
        vcx.update(|window, cx| screen.update(cx, |u, cx| u.appear(window, cx)));
        vcx.run_until_parked();
        (state, screen, vcx)
    }

    fn field_focused(screen: &Entity<UnlockScreen>, vcx: &mut VisualTestContext) -> bool {
        vcx.update(|window, cx| {
            let password = screen.read(cx).password.clone();
            password.read(cx).focus_handle(cx).is_focused(window)
        })
    }

    #[gpui::test]
    fn unlocking_shows_a_spinner_in_place_of_the_controls(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, screen, mut vcx) = open(dir.path(), cx);
        assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Unlock);
        assert!(vcx.debug_bounds("unlock-password").is_some());
        assert!(vcx.debug_bounds("unlocking").is_none());
        let field = vcx.debug_bounds("unlock-password").unwrap();
        let card = vcx.debug_bounds("unlock-card").unwrap();
        // The app icon sits at the top of the card at 128 pt, above the field.
        let icon = vcx.debug_bounds("unlock-icon").expect("app icon");
        assert_eq!(icon.size, gpui::size(px(APP_ICON_SIZE), px(APP_ICON_SIZE)));
        assert!(icon.bottom() <= field.top());
        assert!(icon.top() >= card.top());

        for busy in [Busy::Unlocking, Busy::TouchUnlocking] {
            state.update(&mut vcx, |s, cx| {
                s.busy = Some(busy);
                cx.notify();
            });
            vcx.run_until_parked();
            let spinner = vcx
                .debug_bounds("unlocking")
                .expect("spinner while unlocking");
            assert!(
                vcx.debug_bounds("unlock-password").is_none(),
                "no field while unlocking"
            );
            // The overlay covers the controls, starting at the field's top edge.
            assert_eq!(spinner.top(), field.top());
            // Nothing jumps: the card keeps its size and place.
            assert_eq!(vcx.debug_bounds("unlock-card"), Some(card));
            assert_eq!(vcx.debug_bounds("unlock-icon"), Some(icon), "icon stays");

            // Esc does nothing while unlocking.
            vcx.simulate_keystrokes("escape");
            vcx.run_until_parked();
            state.read_with(&vcx, |s, _| {
                assert_eq!(s.busy, Some(busy));
                assert_eq!(s.screen, Screen::Unlock);
            });
            state.update(&mut vcx, |s, cx| {
                s.busy = None;
                cx.notify();
            });
            vcx.run_until_parked();
            assert!(vcx.debug_bounds("unlocking").is_none());
        }
        assert!(
            field_focused(&screen, &mut vcx),
            "re-focused after unlocking"
        );
    }

    #[gpui::test]
    fn wrong_password_returns_to_the_focused_field(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, screen, mut vcx) = open(dir.path(), cx);
        vcx.update(|window, cx| window.blur(cx));
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("wrong".into()), cx);
            assert_eq!(s.busy, Some(Busy::Unlocking));
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.locked && s.busy.is_none());
            assert_eq!(s.unlock_failures, 1);
            assert!(s.error.is_some());
        });
        assert!(vcx.debug_bounds("unlock-password").is_some());
        assert!(vcx.debug_bounds("unlocking").is_none());
        assert!(field_focused(&screen, &mut vcx));
    }
}
