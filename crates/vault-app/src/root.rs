//! Window root: picks the screen from `AppState`, persists window geometry, shows toasts.

use std::time::Duration;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui::{
    Animation, AnimationExt as _, AnyElement, AppContext as _, Context, Entity,
    InteractiveElement as _, IntoElement, ParentElement as _, Render, Styled as _, Subscription,
    Task, Window, div, ease_out_quint, prelude::FluentBuilder as _, px,
};
use gpui_component::{ActiveTheme as _, WindowExt as _};
use gpui_kit_assets::IconName;

use crate::actions;
use crate::autolock::{self, LockTriggers};
use crate::persist::{self, WindowState};
use crate::screens::{ChooseScreen, ColumnsResized, MainScreen, SettingsView, UnlockScreen};
use crate::state::{AppState, Screen, ToastPlace};
use crate::{theme, ui};

#[cfg(test)]
thread_local! {
    /// How often the capture exclusion ran on this (test) thread.
    static CAPTURE_EXCLUSIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Debug builds only: set to `1` at launch to keep app windows visible to screenshots, so
/// UI screenshots can be taken for review. Release builds never read it.
const ALLOW_CAPTURE_ENV: &str = "VAULT_ALLOW_SCREEN_CAPTURE";

/// Whether app windows are hidden from screen capture. `debug` is
/// `cfg!(debug_assertions)`; `env_value` is `VAULT_ALLOW_SCREEN_CAPTURE` and only counts
/// when `debug` is true, so a release build always excludes.
fn capture_exclusion_enabled(debug: bool, env_value: Option<&str>) -> bool {
    !(debug && env_value == Some("1"))
}

/// The capture-exclusion decision, made once at launch (the first `VaultRoot`). Tests
/// set it directly instead of touching the process environment.
#[derive(Clone, Copy)]
struct CaptureExclusion(bool);

impl gpui::Global for CaptureExclusion {}

impl CaptureExclusion {
    fn from_launch() -> Self {
        let debug = cfg!(debug_assertions);
        // Release builds do not read the variable at all.
        let env = if debug {
            std::env::var(ALLOW_CAPTURE_ENV).ok()
        } else {
            None
        };
        let enabled = capture_exclusion_enabled(debug, env.as_deref());
        if !enabled {
            log::warn!(
                "screen-capture exclusion disabled (VAULT_ALLOW_SCREEN_CAPTURE, debug build only)"
            );
        }
        Self(enabled)
    }
}

/// Hides every app window from screenshots and screen recording (NSWindow
/// `sharingType = none`). Apple documents this as legacy and best effort: ScreenCaptureKit
/// on recent macOS may ignore it. Observed on the owner's Mac (macOS 27): system
/// screenshots of excluded windows come out blank, so it is effective in practice.
/// A no-op off the main thread (e.g. in tests), and skipped when [`CaptureExclusion`] is
/// off.
fn exclude_windows_from_capture(cx: &gpui::App) {
    if cx.try_global::<CaptureExclusion>().is_some_and(|c| !c.0) {
        return;
    }
    vault_macos::exclude_app_windows_from_capture();
    #[cfg(test)]
    CAPTURE_EXCLUSIONS.with(|c| c.set(c.get() + 1));
}

/// Keeps the theme accent in step with the macOS accent colour (05 §5). The AppKit
/// observer only pushes into a channel; a main-thread task rebuilds the theme. Drop on
/// the main thread.
struct SystemAccentWatch {
    _observer: vault_macos::Subscription,
    _task: Task<()>,
}

impl SystemAccentWatch {
    fn install(cx: &mut Context<VaultRoot>) -> Self {
        let (tx, mut rx) = mpsc::unbounded::<()>();
        let observer = vault_macos::on_system_colors_changed(move || {
            let _ = tx.unbounded_send(());
        });
        let task = cx.spawn(async move |this, cx| {
            while rx.next().await.is_some() {
                let alive = this.update(cx, |_, cx| {
                    theme::reapply(cx);
                    cx.notify();
                });
                if alive.is_err() {
                    break;
                }
            }
        });
        Self {
            _observer: observer,
            _task: task,
        }
    }
}

/// Locked → unlocked crossfade (§2.3).
const CROSSFADE: Duration = Duration::from_millis(150);
/// Window geometry is written this long after the last resize/move.
const SAVE_DEBOUNCE: Duration = Duration::from_millis(500);

pub struct VaultRoot {
    state: Entity<AppState>,
    choose: Entity<ChooseScreen>,
    unlock: Entity<UnlockScreen>,
    main: Entity<MainScreen>,
    settings: Entity<SettingsView>,
    screen: Screen,
    geometry: WindowState,
    save_geometry: Option<Task<()>>,
    _subscriptions: Vec<Subscription>,
    _triggers: LockTriggers,
    _system_accent: SystemAccentWatch,
}

impl VaultRoot {
    pub fn new(
        state: Entity<AppState>,
        restore: Option<WindowState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        if !cx.has_global::<CaptureExclusion>() {
            cx.set_global(CaptureExclusion::from_launch());
        }
        // Tests inject their own accent source; the app reads AppKit's. The window's
        // theme was applied before this source existed, so apply it again.
        #[cfg(not(test))]
        if !cx.has_global::<theme::AccentSource>() {
            cx.set_global(theme::AccentSource::system());
            theme::apply(window, cx);
        }
        let columns = restore.and_then(|r| r.columns);
        let choose = cx.new(|cx| ChooseScreen::new(state.clone(), window, cx));
        let unlock = cx.new(|cx| UnlockScreen::new(state.clone(), window, cx));
        let main = cx.new(|cx| MainScreen::new(state.clone(), columns, window, cx));
        let settings = cx.new(|cx| SettingsView::new(state.clone(), window, cx));

        let subscriptions = vec![
            cx.observe_window_appearance(window, |_, window, cx| theme::apply(window, cx)),
            cx.observe_in(&state, window, |this, state, window, cx| {
                let (screen, request) = {
                    let s = state.read(cx);
                    (s.screen, s.choose_request.is_some())
                };
                if screen != this.screen {
                    let was_unlock = this.screen == Screen::Unlock;
                    if this.screen == Screen::Unlock {
                        this.unlock.update(cx, |u, cx| u.disappear(window, cx));
                    }
                    this.screen = screen;
                    this.appear(window, cx);
                    if was_unlock && screen == Screen::Main {
                        this.main.update(cx, |m, cx| m.focus_search(window, cx));
                    }
                } else if screen == Screen::Choose && request {
                    this.appear(window, cx);
                }
                this.sync_settings(window, cx);
                cx.notify();
            }),
            cx.observe_window_bounds(window, |this, window, cx| {
                this.geometry = ui::window_geometry(window, this.geometry.columns);
                this.schedule_save(cx);
            }),
            cx.subscribe_in(&main, window, |this, _, ev: &ColumnsResized, _, cx| {
                this.geometry.columns = Some(ev.0);
                this.schedule_save(cx);
            }),
            // Every window (this one, backup viewers) is wrapped in a gpui-component
            // `Root`; deferred so the NSWindow is registered with NSApp first.
            cx.observe_new::<gpui_component::Root>(|_, _, cx| {
                cx.defer(|cx| exclude_windows_from_capture(cx));
            }),
        ];

        let weak = cx.entity().downgrade();
        window.on_window_should_close(cx, move |window, cx| {
            weak.update(cx, |this, cx| {
                this.geometry = ui::window_geometry(window, this.geometry.columns);
                this.save_geometry = None;
                persist::save_window_state(&this.geometry);
                this.state.update(cx, |s, cx| s.lock(cx));
            })
            .ok();
            true
        });

        cx.set_global(actions::MainWindow(window.window_handle().window_id()));
        let screen = state.read(cx).screen;
        cx.defer_in(window, |this, window, cx| {
            exclude_windows_from_capture(cx);
            this.appear(window, cx);
        });
        let triggers = autolock::install(&state, cx);
        let system_accent = SystemAccentWatch::install(cx);
        Self {
            geometry: ui::window_geometry(window, columns),
            state,
            choose,
            unlock,
            main,
            settings,
            screen,
            save_geometry: None,
            _subscriptions: subscriptions,
            _triggers: triggers,
            _system_accent: system_accent,
        }
    }

    /// Focus the right control for the screen that just became visible.
    fn appear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.screen {
            Screen::Choose => self.choose.update(cx, |c, cx| c.appear(window, cx)),
            Screen::Unlock => self.unlock.update(cx, |u, cx| u.appear(window, cx)),
            Screen::Main => self.main.update(cx, |m, cx| m.appear(window, cx)),
        }
    }

    /// Opens or closes the settings dialog to match `AppState::settings_open`.
    fn sync_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let want = self.state.read(cx).settings_open;
        let have = window.has_active_dialog(cx);
        if want && !have {
            let (view, state) = (self.settings.clone(), self.state.clone());
            window.open_dialog(cx, move |dialog, _, _| {
                let (state, close) = (state.clone(), state.clone());
                // Our own close button: gpui-component's built-in one keeps the arrow
                // cursor and takes no style.
                let title = ui::h_flex()
                    .w_full()
                    .justify_between()
                    .child("Settings")
                    .child(
                        ui::icon_button("settings-close", IconName::Close, "Close  Esc").on_click(
                            move |_, _, cx| close.update(cx, |s, cx| s.open_settings(false, cx)),
                        ),
                    );
                dialog
                    .title(title)
                    .close_button(false)
                    .w(px(560.))
                    .child(view.clone())
                    .on_close(move |_, _, cx| state.update(cx, |s, cx| s.open_settings(false, cx)))
            });
        } else if !want && have {
            window.close_dialog(cx);
        }
    }

    fn schedule_save(&mut self, cx: &mut Context<Self>) {
        let geometry = self.geometry;
        // Replacing the task cancels the previous pending write.
        self.save_geometry = Some(cx.spawn(async move |_, cx| {
            cx.background_executor().timer(SAVE_DEBOUNCE).await;
            persist::save_window_state(&geometry);
        }));
    }

    fn touch(&mut self, cx: &mut Context<Self>) {
        self.state.update(cx, |s, _| s.touch_activity());
    }
}

impl Render for VaultRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Text size step (05 §6): every rem-based size follows the window rem.
        let rem = theme::rem_size(cx);
        if window.rem_size() != rem {
            window.set_rem_size(rem);
        }
        let state = self.state.read(cx);
        // On the main screen, detail toasts ("Copied") draw in the detail column.
        let toast = state
            .toast
            .as_ref()
            .filter(|t| self.screen != Screen::Main || t.place == ToastPlace::Window)
            .map(|t| t.message.clone());
        let unlock_count = state.unlock_count;
        let reduce_motion = state.reduce_motion;
        let theme = cx.theme();

        let content: AnyElement = match self.screen {
            Screen::Choose => self.choose.clone().into_any_element(),
            Screen::Unlock => self.unlock.clone().into_any_element(),
            Screen::Main if reduce_motion => self.main.clone().into_any_element(),
            Screen::Main => div()
                .size_full()
                .child(self.main.clone())
                .with_animation(
                    ("unlock-fade", unlock_count),
                    Animation::new(CROSSFADE).with_easing(ease_out_quint()),
                    |el, t| el.opacity(t),
                )
                .into_any_element(),
        };

        div()
            .id("vault-root")
            .size_full()
            .relative()
            .bg(theme.background)
            .text_color(theme.foreground)
            .text_size(theme.font_size)
            .capture_any_mouse_down(cx.listener(|this, _, _, cx| this.touch(cx)))
            .capture_key_down(cx.listener(|this, _, _, cx| this.touch(cx)))
            // The window claims its titlebar (`app_owns_titlebar_drag`), so it moves only by
            // a drag band painted under the content. The main screen draws its own.
            .when(self.screen != Screen::Main, |root| {
                root.child(ui::window_drag_band())
            })
            .child(content)
            .when_some(toast, |root, message| {
                root.child(
                    ui::h_flex()
                        .absolute()
                        .bottom(px(20.))
                        .left_0()
                        .right_0()
                        .justify_center()
                        .child(ui::pill(message, cx)),
                )
            })
    }
}

#[cfg(test)]
#[path = "root_tests.rs"]
mod tests;
