//! Unlock (specs/05-ui.md §2.2), with Touch ID when enrolled and the policy allows
//! (specs/04-macos.md §2). Touch ID starts by itself when the screen appears after the
//! vault was opened, and on the next window activation after a lock.
//!
//! While a password or Touch ID unlock is being verified the controls are hidden (kept
//! in the layout so the card does not change size) while the icon's wheel turns: a
//! rotated SVG of the six spokes over a copy of the icon without them.

use std::f32::consts::PI;
use std::time::Duration;

use gpui::{
    Animation, AnimationExt as _, AnyElement, Context, Entity, FontWeight, InteractiveElement as _,
    IntoElement, ParentElement as _, Render, StatefulInteractiveElement as _, Styled as _,
    Subscription, Transformation, Window, div, ease_in_out, img, percentage,
    prelude::FluentBuilder as _, px, rgb, svg,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;

/// Side of the app icon on the unlock card, in points (the raster is 2x this).
const APP_ICON_SIZE: f32 = 128.;
/// `wheel.svg`'s 512-unit view box, centred on the hub at (486, 503) of the 1024-unit
/// icon, in points of the 128 pt icon slot: (28.75, 30.875), snapped to the half points
/// layout rounds to on Retina. The 1/8 pt offset is invisible.
const WHEEL_SIZE: f32 = 64.;
const WHEEL_LEFT: f32 = 28.5;
const WHEEL_TOP: f32 = 31.;
/// One ease-in-out turn of the wheel.
const WHEEL_TURN: Duration = Duration::from_millis(1920);
/// Mid-tone of the icon's `steelBar` gradient: gpui draws SVGs as a one-colour mask.
const WHEEL_STEEL: u32 = 0xbccadd;

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

/// Status text centred over the hidden controls.
fn unlocking_overlay(cx: &gpui::App) -> impl IntoElement {
    ui::v_flex()
        .absolute()
        .inset_0()
        .items_center()
        .justify_center()
        .id("unlocking")
        .debug_selector(|| "unlocking".into())
        .aria_label("Unlocking")
        .child(
            div()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child("Unlocking…"),
        )
}

/// The icon's spokes, turning over the spoke-less icon (same motion as gpui-component's
/// `Spinner`). Only built while an unlock runs and Reduce Motion is off.
fn wheel() -> impl IntoElement {
    svg()
        .path(crate::assets::APP_ICON_WHEEL)
        .debug_selector(|| "unlock-wheel-animation".into())
        .absolute()
        .left(px(WHEEL_LEFT))
        .top(px(WHEEL_TOP))
        .size(px(WHEEL_SIZE))
        .text_color(rgb(WHEEL_STEEL))
        .with_animation(
            "unlock-wheel",
            Animation::new(WHEEL_TURN).repeat().with_easing(ease_in_out),
            |wheel, t| wheel.with_transformation(Transformation::rotate(percentage(t))),
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
        let spinning = unlocking && !reduce_motion;
        let still = if spinning {
            crate::assets::APP_ICON_SPOKELESS
        } else {
            crate::assets::APP_ICON
        };
        let icon = div()
            .relative()
            .size_full()
            .child(
                img(still)
                    .size_full()
                    .debug_selector(|| "unlock-icon-still".into()),
            )
            .when(spinning, |icon| icon.child(wheel()));

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
                    .relative()
                    .flex_shrink_0()
                    .debug_selector(|| "unlock-icon".into())
                    .child(icon),
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

        // Each wrong password gets a fresh element id, which restarts the animation. The
        // count is zero after a lock or unlock (`AppState::lock`), so the screen appearing
        // never replays an old shake.
        let card: AnyElement = if failures == 0 || reduce_motion {
            card.into_any_element()
        } else {
            div()
                .debug_selector(|| "unlock-shake".into())
                .child(card.relative().with_animation(
                    ("shake", failures),
                    Animation::new(SHAKE),
                    |card, t| card.left(px(shake_offset(t))),
                ))
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
    use crate::state::MIN_UNLOCK_HOLD;

    const MS: Duration = Duration::from_millis(1);

    /// Holds unlocks for the real minimum and makes every background task take `work`
    /// on the fake clock.
    fn timed(state: &Entity<AppState>, work: Duration, vcx: &mut VisualTestContext) {
        state.update(vcx, |s, _| {
            s.unlock_hold = MIN_UNLOCK_HOLD;
            s.fake_work_time = work;
        });
    }

    /// Runs ready tasks and fires timers due within `by`, ending with the clock at `by`.
    fn advance(by: Duration, vcx: &mut VisualTestContext) {
        vcx.executor().advance_clock(by);
    }

    fn unlocking(state: &Entity<AppState>, vcx: &mut VisualTestContext) -> bool {
        state.read_with(vcx, |s, _| s.busy == Some(Busy::Unlocking))
    }

    fn unlock(state: &Entity<AppState>, password: &str, vcx: &mut VisualTestContext) {
        state.update(vcx, |s, cx| {
            s.unlock(SecretString::new(password.into()), cx)
        });
    }

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
    fn reduce_motion_keeps_the_icon_still(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        let icon = vcx.debug_bounds("unlock-icon").unwrap();
        state.update(&mut vcx, |s, cx| {
            s.set_reduce_motion(true, cx);
            s.busy = Some(Busy::Unlocking);
            cx.notify();
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlocking").is_some());
        assert!(vcx.debug_bounds("unlock-wheel-animation").is_none());
        assert_eq!(vcx.debug_bounds("unlock-icon-still"), Some(icon));
    }

    #[gpui::test]
    fn unlocking_spins_icon_in_place_of_the_controls(cx: &mut TestAppContext) {
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
            let status = vcx
                .debug_bounds("unlocking")
                .expect("status while unlocking");
            assert!(
                vcx.debug_bounds("unlock-password").is_none(),
                "no field while unlocking"
            );
            // The overlay covers the controls, starting at the field's top edge.
            assert_eq!(status.top(), field.top());
            // Nothing jumps: the card keeps its size and place.
            assert_eq!(vcx.debug_bounds("unlock-card"), Some(card));
            assert_eq!(vcx.debug_bounds("unlock-icon"), Some(icon), "icon stays");
            assert_eq!(
                vcx.debug_bounds("unlock-icon-still"),
                Some(icon),
                "still icon remains behind the animation"
            );
            let wheel = vcx
                .debug_bounds("unlock-wheel-animation")
                .expect("animated wheel over the still icon");
            assert_eq!(wheel.size, gpui::size(px(WHEEL_SIZE), px(WHEEL_SIZE)));
            assert_eq!(wheel.left(), icon.left() + px(WHEEL_LEFT));
            assert_eq!(wheel.top(), icon.top() + px(WHEEL_TOP));

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

    #[gpui::test]
    fn lock_does_not_replay_the_shake(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        assert!(vcx.debug_bounds("unlock-shake").is_none());

        // Wrong password: shake.
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("bad".into()), cx)
        });
        vcx.run_until_parked();
        assert!(
            vcx.debug_bounds("unlock-shake").is_some(),
            "wrong password shakes"
        );

        // ⌘L / idle / sidebar Lock while the error is showing: the next unlock screen
        // starts still.
        state.update(&mut vcx, |s, cx| s.lock(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.unlock_failures, 0));
        assert!(
            vcx.debug_bounds("unlock-shake").is_none(),
            "no shake after lock"
        );

        // Fail, unlock, lock: the old failure does not shake the new unlock screen.
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("bad".into()), cx)
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlock-shake").is_some());
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("pw".into()), cx)
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.screen, Screen::Main));
        state.update(&mut vcx, |s, cx| s.lock(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.screen, Screen::Unlock));
        assert!(
            vcx.debug_bounds("unlock-shake").is_none(),
            "no shake after lock"
        );
        assert!(vcx.debug_bounds("unlock-card").is_some());

        // A wrong password still shakes afterwards.
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("bad".into()), cx)
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlock-shake").is_some());
    }

    #[gpui::test]
    fn fast_unlock_holds_until_the_minimum(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        timed(&state, 50 * MS, &mut vcx);
        unlock(&state, "pw", &mut vcx);
        // Decrypted at 50 ms, still "Unlocking…" at 499 ms.
        advance(MIN_UNLOCK_HOLD - MS, &mut vcx);
        assert!(unlocking(&state, &mut vcx), "held at 499 ms");
        assert!(
            state.read_with(&vcx, |s, _| s.vault.is_none()),
            "result waits"
        );
        assert!(vcx.debug_bounds("unlocking").is_some());
        advance(MS, &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.screen, Screen::Main, "shown at 500 ms");
            assert!(!s.locked && s.busy.is_none());
        });
    }

    #[gpui::test]
    fn slow_unlock_is_not_delayed(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        timed(&state, 800 * MS, &mut vcx);
        unlock(&state, "pw", &mut vcx);
        advance(800 * MS - MS, &mut vcx);
        assert!(unlocking(&state, &mut vcx), "still decrypting at 799 ms");
        // Shown the moment decryption finishes, with no hold on top.
        advance(MS, &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.screen, Screen::Main);
            assert!(s.busy.is_none());
        });
    }

    #[gpui::test]
    fn failed_unlock_holds_too(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        timed(&state, 50 * MS, &mut vcx);
        unlock(&state, "bad", &mut vcx);
        advance(MIN_UNLOCK_HOLD - MS, &mut vcx);
        assert!(unlocking(&state, &mut vcx));
        state.read_with(&vcx, |s, _| {
            assert!(s.error.is_none() && s.unlock_failures == 0);
        });
        assert!(vcx.debug_bounds("unlock-shake").is_none(), "no early shake");
        advance(MS, &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert!(s.busy.is_none() && s.error.is_some());
            assert_eq!(s.unlock_failures, 1);
        });
        assert!(vcx.debug_bounds("unlock-shake").is_some());

        // A slow failure shows the moment it is known.
        timed(&state, 800 * MS, &mut vcx);
        unlock(&state, "bad", &mut vcx);
        advance(800 * MS - MS, &mut vcx);
        assert!(unlocking(&state, &mut vcx));
        advance(MS, &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert!(s.busy.is_none());
            assert_eq!(s.unlock_failures, 2);
        });
    }

    #[gpui::test]
    fn lock_or_switch_during_the_hold_discards_the_result(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        timed(&state, 50 * MS, &mut vcx);
        unlock(&state, "pw", &mut vcx);
        advance(100 * MS, &mut vcx);
        assert!(unlocking(&state, &mut vcx), "decrypted, holding");
        state.update(&mut vcx, |s, cx| s.lock(cx));
        advance(MIN_UNLOCK_HOLD, &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert!(s.locked && s.busy.is_none());
            assert_eq!(s.screen, Screen::Unlock);
            assert!(s.vault.as_ref().is_some_and(|v| v.vault().is_none()));
        });

        unlock(&state, "pw", &mut vcx);
        advance(100 * MS, &mut vcx);
        assert!(unlocking(&state, &mut vcx));
        state.update(&mut vcx, |s, cx| s.switch_vault(ChooseIntent::Home, cx));
        advance(MIN_UNLOCK_HOLD, &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert!(s.locked && s.vault.is_none());
            assert_eq!(s.screen, Screen::Choose);
        });
    }
}
