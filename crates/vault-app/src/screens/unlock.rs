//! Unlock (specs/05-ui.md §2.2), with Touch ID when enrolled and the policy allows
//! (specs/04-macos.md §2). Touch ID starts by itself when the screen appears after the
//! vault was opened, and on the next window activation after a lock.
//!
//! While a password or Touch ID unlock is being verified the controls are hidden (kept
//! in the layout so the card does not change size) while the icon's wheel turns: a
//! rotated SVG of the six spokes over a copy of the icon without them.

use std::cell::Cell;
use std::f32::consts::PI;
use std::rc::Rc;
use std::time::Duration;

use gpui::{
    Animation, AnimationExt as _, AnyElement, Context, Entity, InteractiveElement as _,
    IntoElement, ParentElement as _, Render, StatefulInteractiveElement as _, Styled as _,
    Subscription, Task, Transformation, Window, div, ease_out_quint, img, percentage,
    prelude::FluentBuilder as _, px, rgb, svg,
};
use gpui_component::button::{Button, ButtonCustomVariant, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _};
use gpui_kit_assets::IconName;

/// Side of the app icon on the unlock card, in points (the raster is 2x this).
const APP_ICON_SIZE: f32 = 128.;
/// `wheel.svg`'s 512-unit view box, centred on the hub at (486, 503) of the 1024-unit
/// icon, scaled to the 128 pt icon slot.
const WHEEL_SIZE: f32 = 64.;
const WHEEL_LEFT: f32 = 28.5;
const WHEEL_TOP: f32 = 31.;
/// The two PNGs differ only in source pixels x=60..181, y=60..195. Clip the
/// full icon to that area (with a 4 px margin) so its translucent outer border
/// is not painted twice over the spoke-less background. Coordinates are points.
const STILL_OVERLAY_LEFT: f32 = 28.;
const STILL_OVERLAY_TOP: f32 = 28.;
const STILL_OVERLAY_WIDTH: f32 = 65.;
const STILL_OVERLAY_HEIGHT: f32 = 72.;
/// The wheel makes one quick turn, then continues at a steady pace.
const WHEEL_START: Duration = Duration::from_millis(950);
const WHEEL_TURN: Duration = Duration::from_millis(1920);
const WHEEL_DECAY: f32 = 5.;
const WHEEL_SETTLE: Duration = Duration::from_millis(280);
const WHEEL_CROSSFADE: Duration = Duration::from_millis(160);
/// Mid-tone of the icon's `steelBar` gradient: gpui draws SVGs as a one-colour mask.
const WHEEL_STEEL: u32 = 0xbccadd;

use crate::state::{AppState, Busy, ChooseIntent, Screen, TouchDenied};
use crate::ui::{self, Clickable as _};

const SHAKE: Duration = Duration::from_millis(300);
/// Peak horizontal displacement of the shake.
const SHAKE_PX: f32 = 4.;

pub struct UnlockScreen {
    state: Entity<AppState>,
    password: Entity<InputState>,
    /// Whether the last state notification saw an unlock in flight.
    was_unlocking: bool,
    seen_failures: u32,
    wheel_phase: Rc<Cell<f32>>,
    settling_from: Option<f32>,
    crossfading: bool,
    settle_task: Option<Task<()>>,
    _subscriptions: Vec<Subscription>,
}

impl UnlockScreen {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let password = ui::password_input("Enter master password", window, cx);
        let subscriptions = vec![
            cx.observe_in(&state, window, |this, state, window, cx| {
                let s = state.read(cx);
                let unlocking = is_unlocking(s.busy);
                let failed = s.unlock_failures != this.seen_failures;
                this.seen_failures = s.unlock_failures;
                let reduce_motion = s.reduce_motion;
                let on_unlock_screen = s.screen == Screen::Unlock;
                // A failed unlock brings the field back: put the cursor in it again.
                if this.was_unlocking && !unlocking && on_unlock_screen {
                    ui::focus_input(&this.password, window, cx);
                    if !reduce_motion && failed {
                        let phase = this.wheel_phase.get().fract();
                        if phase > 0.01 {
                            this.settling_from = Some(phase);
                            this.settle_task = Some(cx.spawn(async move |this, cx| {
                                cx.background_executor().timer(WHEEL_SETTLE).await;
                                this.update(cx, |this, cx| {
                                    this.settling_from = None;
                                    this.crossfading = true;
                                    cx.notify();
                                })
                                .ok();
                                cx.background_executor().timer(WHEEL_CROSSFADE).await;
                                this.update(cx, |this, cx| {
                                    this.crossfading = false;
                                    cx.notify();
                                })
                                .ok();
                            }));
                        }
                    }
                } else if unlocking && !this.was_unlocking {
                    this.settling_from = None;
                    this.crossfading = false;
                    this.settle_task = None;
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
            seen_failures: 0,
            wheel_phase: Rc::new(Cell::new(0.)),
            settling_from: None,
            crossfading: false,
            settle_task: None,
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

/// The icon's spokes are mounted from the first frame, so the SVG is ready when
/// unlocking starts. Only the animation changes with the unlock state.
fn wheel() -> gpui::Svg {
    svg()
        .path(crate::assets::APP_ICON_WHEEL)
        .absolute()
        .left(px(WHEEL_LEFT))
        .top(px(WHEEL_TOP))
        .size(px(WHEEL_SIZE))
        .text_color(rgb(WHEEL_STEEL))
}

/// Damped sine: two small swings that settle back to 0 at `t = 1`.
fn shake_offset(t: f32) -> f32 {
    (t * PI * 4.).sin() * SHAKE_PX * (1. - t)
}

/// One complete turn with an exponentially decaying burst of speed. The linear
/// part matches the following loop's speed, so the handoff stays smooth.
fn wheel_start_progress(t: f32) -> f32 {
    let steady = WHEEL_START.as_secs_f32() / WHEEL_TURN.as_secs_f32();
    let burst = (1. - (-WHEEL_DECAY * t).exp()) / (1. - (-WHEEL_DECAY).exp());
    steady * t + (1. - steady) * burst
}

impl Render for UnlockScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let state = self.state.read(cx);
        let name = state.vault_name();
        let unlocking = is_unlocking(state.busy);
        let touch = state.touch_policy();
        let touch_hint = touch.err().and_then(TouchDenied::hint);
        let failures = state.unlock_failures;
        let reduce_motion = state.reduce_motion;
        let theme = cx.theme();
        let vault_label_color = if theme.mode.is_dark() {
            rgb(0xb8b8be).into()
        } else {
            theme.muted_foreground
        };
        let spinning = unlocking && !reduce_motion;
        let settling = !spinning && !reduce_motion && self.settling_from.is_some();
        let crossfading = !spinning && !settling && self.crossfading;
        let wheel: AnyElement = if spinning {
            let phase = self.wheel_phase.clone();
            wheel()
                .debug_selector(|| "unlock-wheel-animation".into())
                .with_animations(
                    "unlock-wheel",
                    vec![
                        Animation::new(WHEEL_START).with_easing(wheel_start_progress),
                        Animation::new(WHEEL_TURN).repeat(),
                    ],
                    move |wheel, _, t| {
                        phase.set(t);
                        wheel.with_transformation(Transformation::rotate(percentage(t)))
                    },
                )
                .into_any_element()
        } else if let Some(from) = self.settling_from.filter(|_| settling) {
            wheel()
                .debug_selector(|| "unlock-wheel-settling".into())
                .with_animation(
                    "unlock-wheel-settle",
                    Animation::new(WHEEL_SETTLE).with_easing(ease_out_quint()),
                    move |wheel, t| {
                        wheel.with_transformation(Transformation::rotate(percentage(
                            from + (1. - from) * t,
                        )))
                    },
                )
                .into_any_element()
        } else {
            wheel()
                .debug_selector(|| "unlock-wheel-still".into())
                .into_any_element()
        };
        let still_image = img(crate::assets::APP_ICON)
            .absolute()
            .left(px(-STILL_OVERLAY_LEFT))
            .top(px(-STILL_OVERLAY_TOP))
            .size(px(APP_ICON_SIZE))
            .debug_selector(|| "unlock-icon-still".into());
        let still_image: AnyElement = if spinning || settling {
            still_image.invisible().into_any_element()
        } else if crossfading {
            still_image
                .debug_selector(|| "unlock-icon-crossfade".into())
                .with_animation(
                    "unlock-icon-crossfade",
                    Animation::new(WHEEL_CROSSFADE - Duration::from_millis(20)),
                    |image, t| image.opacity(t),
                )
                .into_any_element()
        } else {
            still_image.into_any_element()
        };
        let icon = div()
            .relative()
            .size_full()
            .child(
                img(crate::assets::APP_ICON_SPOKELESS)
                    .size_full()
                    .debug_selector(|| "unlock-icon-background".into()),
            )
            .child(wheel)
            .child(
                div()
                    .absolute()
                    .left(px(STILL_OVERLAY_LEFT))
                    .top(px(STILL_OVERLAY_TOP))
                    .w(px(STILL_OVERLAY_WIDTH))
                    .h(px(STILL_OVERLAY_HEIGHT))
                    .overflow_hidden()
                    .debug_selector(|| "unlock-icon-still-clip".into())
                    .child(still_image),
            );

        let password_field = div()
            .w_full()
            .debug_selector(|| "unlock-password".into())
            .child(ui::input(&self.password).disabled(unlocking));
        // Animate only the input. The card and buttons keep their positions.
        let password_field: AnyElement = if failures == 0 || reduce_motion {
            password_field.into_any_element()
        } else {
            div()
                .w_full()
                .debug_selector(|| "unlock-input-shake".into())
                .child(password_field.relative().with_animation(
                    ("shake", failures),
                    Animation::new(SHAKE),
                    |field, t| field.left(px(shake_offset(t))),
                ))
                .into_any_element()
        };
        let mut controls = ui::v_flex().w_full().gap(px(12.)).child(password_field);
        if let Some(hint) = touch_hint {
            controls = controls.child(
                div()
                    .w_full()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(hint),
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
                div()
                    .w_full()
                    .flex()
                    .justify_center()
                    .debug_selector(|| "unlock-switch".into())
                    .child(
                        Button::new("switch")
                            .custom(
                                ButtonCustomVariant::new(cx)
                                    .foreground(theme.foreground.opacity(0.8)),
                            )
                            .small()
                            .accessibility_label("Open another vault")
                            .child("Open another vault…")
                            .child(div().text_color(theme.muted_foreground).child("⌘O"))
                            .disabled(unlocking)
                            .clickable_when(!unlocking)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.state
                                    .update(cx, |s, cx| s.switch_vault(ChooseIntent::Home, cx));
                            })),
                    ),
            )
            // Hidden, not removed: the card keeps its size and nothing jumps. A hidden
            // div paints none of its children, so the field takes no clicks or keys.
            .when(unlocking, |controls| controls.invisible());

        let card = ui::card(cx)
            .w(px(360.))
            .gap(px(20.))
            .items_center()
            .debug_selector(|| "unlock-card".into())
            // The app icon (its PNG already has the macOS squircle and shadow). The
            // fixed box keeps the card size even before the image has decoded.
            .child(
                ui::v_flex()
                    .items_center()
                    .gap(px(10.))
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
                            .text_sm()
                            .text_color(vault_label_color)
                            .overflow_hidden()
                            .text_ellipsis()
                            .debug_selector(|| "unlock-vault-name".into())
                            .child(name),
                    ),
            )
            .child(
                div()
                    .relative()
                    .w_full()
                    .child(controls)
                    .when(unlocking, |area| area.child(unlocking_overlay(cx))),
            );

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

    #[test]
    fn wheel_start_ends_at_loop_speed() {
        assert!(wheel_start_progress(0.).abs() < 1e-6);
        assert!((wheel_start_progress(1.) - 1.).abs() < 1e-6);
        assert!(wheel_start_progress(0.25) > 0.25);

        let step = 0.001;
        let end_speed = (1. - wheel_start_progress(1. - step)) / (step * WHEEL_START.as_secs_f32());
        let loop_speed = 1. / WHEEL_TURN.as_secs_f32();
        assert!((end_speed - loop_speed).abs() < 0.05);
    }

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
        assert_eq!(vcx.debug_bounds("unlock-icon-background"), Some(icon));
    }

    #[gpui::test]
    fn failed_unlock_finishes_wheel_before_restoring_still_icon(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, screen, mut vcx) = open(dir.path(), cx);
        state.update(&mut vcx, |s, cx| {
            s.busy = Some(Busy::Unlocking);
            cx.notify();
        });
        vcx.run_until_parked();
        vcx.update(|_, cx| screen.read(cx).wheel_phase.set(0.4));
        state.update(&mut vcx, |s, cx| {
            s.busy = None;
            s.unlock_failures += 1;
            cx.notify();
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlock-wheel-settling").is_some());
        assert!(vcx.debug_bounds("unlock-password").is_some());
        advance(WHEEL_SETTLE, &mut vcx);
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlock-icon-crossfade").is_some());
        assert!(vcx.debug_bounds("unlock-wheel-settling").is_none());
        advance(Duration::from_millis(160), &mut vcx);
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlock-wheel-still").is_some());
    }

    #[gpui::test]
    fn unlock_keeps_the_background_icon_mounted(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        let icon = vcx.debug_bounds("unlock-icon").unwrap();
        assert_eq!(
            vcx.debug_bounds("unlock-icon-background"),
            Some(icon),
            "the spoke-less background must be decoded before the first unlock"
        );
        assert!(vcx.debug_bounds("unlock-wheel-still").is_some());
        state.update(&mut vcx, |s, cx| {
            s.busy = Some(Busy::Unlocking);
            cx.notify();
        });
        vcx.run_until_parked();
        assert_eq!(vcx.debug_bounds("unlock-icon-background"), Some(icon));
        assert!(vcx.debug_bounds("unlock-wheel-animation").is_some());
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
        // The 256 px asset is drawn at 128 pt.
        let icon = vcx.debug_bounds("unlock-icon").expect("app icon");
        assert_eq!(icon.size, gpui::size(px(128.), px(128.)));
        let still_clip = vcx.debug_bounds("unlock-icon-still-clip").unwrap();
        assert_eq!(still_clip.left(), icon.left() + px(STILL_OVERLAY_LEFT));
        assert_eq!(still_clip.top(), icon.top() + px(STILL_OVERLAY_TOP));
        assert_eq!(
            still_clip.size,
            gpui::size(px(STILL_OVERLAY_WIDTH), px(STILL_OVERLAY_HEIGHT))
        );
        assert!(
            still_clip.right() < icon.right(),
            "outer border stays single-layered"
        );
        assert!(icon.bottom() <= field.top());
        assert!(icon.top() >= card.top());
        let vault_name = vcx.debug_bounds("unlock-vault-name").unwrap();
        assert_eq!(vault_name.top() - icon.bottom(), px(10.));
        assert!(vault_name.bottom() < field.top());
        assert_eq!(field.top() - vault_name.bottom(), px(20.));

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
            assert_eq!(vcx.debug_bounds("unlock-icon-background"), Some(icon));
            assert_eq!(
                vcx.debug_bounds("unlock-icon-still"),
                Some(icon),
                "the original PNG stays mounted during animation"
            );
            let wheel = vcx
                .debug_bounds("unlock-wheel-animation")
                .expect("animated wheel over the still icon");
            assert_eq!(wheel.size, gpui::size(px(WHEEL_SIZE), px(WHEEL_SIZE)));
            // GPUI snaps quarter-point offsets to Retina pixel boundaries.
            assert!((wheel.left() - icon.left() - px(WHEEL_LEFT)).abs() <= px(0.5));
            assert!((wheel.top() - icon.top() - px(WHEEL_TOP)).abs() <= px(0.5));

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
    fn open_another_vault_is_a_clickable_secondary_action(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        let switch = vcx.debug_bounds("unlock-switch").unwrap();
        vcx.simulate_click(switch.center(), gpui::Modifiers::none());
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.screen, Screen::Choose));
    }

    #[gpui::test]
    fn wrong_password_returns_to_the_focused_field(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, screen, mut vcx) = open(dir.path(), cx);
        let card = vcx.debug_bounds("unlock-card").unwrap();
        let switch = vcx.debug_bounds("unlock-switch").unwrap();
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
        assert_eq!(vcx.debug_bounds("unlock-card"), Some(card));
        assert_eq!(vcx.debug_bounds("unlock-switch"), Some(switch));
        assert!(vcx.debug_bounds("unlock-input-shake").is_some());
        assert!(field_focused(&screen, &mut vcx));
    }

    #[gpui::test]
    fn lock_does_not_replay_the_shake(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, mut vcx) = open(dir.path(), cx);
        assert!(vcx.debug_bounds("unlock-input-shake").is_none());

        // Wrong password: shake.
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("bad".into()), cx)
        });
        vcx.run_until_parked();
        assert!(
            vcx.debug_bounds("unlock-input-shake").is_some(),
            "wrong password shakes"
        );

        // ⌘L / idle / sidebar Lock after a failure: the next unlock screen starts still.
        state.update(&mut vcx, |s, cx| s.lock(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.unlock_failures, 0));
        assert!(
            vcx.debug_bounds("unlock-input-shake").is_none(),
            "no shake after lock"
        );

        // Fail, unlock, lock: the old failure does not shake the new unlock screen.
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("bad".into()), cx)
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlock-input-shake").is_some());
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("pw".into()), cx)
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.screen, Screen::Main));
        state.update(&mut vcx, |s, cx| s.lock(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| assert_eq!(s.screen, Screen::Unlock));
        assert!(
            vcx.debug_bounds("unlock-input-shake").is_none(),
            "no shake after lock"
        );
        assert!(vcx.debug_bounds("unlock-card").is_some());

        // A wrong password still shakes afterwards.
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("bad".into()), cx)
        });
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("unlock-input-shake").is_some());
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
        assert!(
            vcx.debug_bounds("unlock-input-shake").is_none(),
            "no early shake"
        );
        advance(MS, &mut vcx);
        state.read_with(&vcx, |s, _| {
            assert!(s.busy.is_none() && s.error.is_some());
            assert_eq!(s.unlock_failures, 1);
        });
        assert!(vcx.debug_bounds("unlock-input-shake").is_some());

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
