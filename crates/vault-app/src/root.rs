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
                    if this.screen == Screen::Unlock {
                        this.unlock.update(cx, |u, cx| u.disappear(window, cx));
                    }
                    this.screen = screen;
                    this.appear(window, cx);
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
                let state = state.clone();
                dialog
                    .title("Settings")
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
mod tests {
    use gpui::{TestAppContext, VisualTestContext};
    use gpui_component::Root;
    use vault_core::Uuid;

    use super::*;
    use crate::actions;
    use crate::state::Settings;

    /// Capture exclusion runs (headless: a no-op, no panic) when the main window opens
    /// and again for each later window, such as a backup viewer.
    #[gpui::test]
    fn windows_are_excluded_from_capture(cx: &mut TestAppContext) {
        let calls = || CAPTURE_EXCLUSIONS.with(|c| c.get());
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(gpui_component::init);
        // What launch decides without VAULT_ALLOW_SCREEN_CAPTURE (pinned so a developer's
        // shell environment cannot change the test).
        cx.update(|cx| cx.set_global(CaptureExclusion(capture_exclusion_enabled(true, None))));
        let before = calls();
        cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        cx.run_until_parked();
        let after_main = calls();
        assert!(after_main > before, "main window");
        cx.add_window(|window, cx| {
            let view = cx.new(|_| gpui::Empty);
            Root::new(view, window, cx)
        });
        cx.run_until_parked();
        assert!(calls() > after_main, "second window");
    }

    /// Debug build with VAULT_ALLOW_SCREEN_CAPTURE=1: no window is excluded. (The
    /// decision is injected as launch would make it; setting the real environment
    /// variable needs `unsafe` and would race other tests.)
    #[gpui::test]
    fn debug_escape_hatch_skips_capture_exclusion(cx: &mut TestAppContext) {
        let calls = || CAPTURE_EXCLUSIONS.with(|c| c.get());
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(gpui_component::init);
        let enabled = capture_exclusion_enabled(true, Some("1"));
        assert!(!enabled);
        cx.update(|cx| cx.set_global(CaptureExclusion(enabled)));
        let before = calls();
        cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        cx.add_window(|window, cx| {
            let view = cx.new(|_| gpui::Empty);
            Root::new(view, window, cx)
        });
        cx.run_until_parked();
        assert_eq!(calls(), before, "no exclusion with the escape hatch on");
    }

    /// Only a debug build with the variable set to exactly `1` skips the exclusion;
    /// release ignores the variable whatever its value.
    #[test]
    fn capture_exclusion_gating() {
        assert!(!capture_exclusion_enabled(true, Some("1")));
        assert!(capture_exclusion_enabled(true, None));
        assert!(capture_exclusion_enabled(true, Some("0")));
        assert!(capture_exclusion_enabled(true, Some("true")));
        assert!(capture_exclusion_enabled(true, Some("")));
        assert!(capture_exclusion_enabled(false, Some("1")));
        assert!(capture_exclusion_enabled(false, None));
    }

    #[gpui::test]
    fn choose_screen_moves_by_the_title_band(cx: &mut TestAppContext) {
        use gpui::{Modifiers, MouseButton, point};
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(gpui_component::init);
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.run_until_parked();
        assert!(vcx.debug_bounds("window-drag-band").is_some());
        let before = ui::window_moves();
        let at = point(px(300.), px(20.));
        vcx.simulate_mouse_down(at, MouseButton::Left, Modifiers::default());
        vcx.simulate_mouse_move(
            at + point(px(6.), px(0.)),
            MouseButton::Left,
            Modifiers::default(),
        );
        assert_eq!(ui::window_moves(), before + 1);
    }

    #[gpui::test]
    fn settings_sheet_opens_applies_and_closes(cx: &mut TestAppContext) {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.run_until_parked();

        // ⌘, works from any screen (here: choose vault) and opens the dialog.
        vcx.simulate_keystrokes("cmd-,");
        assert!(state.read_with(&vcx, |s, _| s.settings_open));
        assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));

        // A General-tab change is live in AppState.
        state.update(&mut vcx, |s, cx| {
            s.update_settings(cx, |st| st.clipboard_clear_secs = 90)
        });
        vcx.run_until_parked();
        assert_eq!(
            state.read_with(&vcx, |s, _| s.settings.clone()),
            Settings {
                clipboard_clear_secs: 90,
                ..Settings::default()
            }
        );

        // Esc closes it and the state follows; ⌘, opens it again.
        vcx.simulate_keystrokes("escape");
        vcx.run_until_parked();
        assert!(!vcx.update(|window, cx| window.has_active_dialog(cx)));
        assert!(!state.read_with(&vcx, |s, _| s.settings_open));
        vcx.simulate_keystrokes("cmd-,");
        assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));
        state.update(&mut vcx, |s, cx| s.open_settings(false, cx));
        vcx.run_until_parked();
        assert!(!vcx.update(|window, cx| window.has_active_dialog(cx)));
    }

    /// Locking (here the same `lock` every trigger calls) closes the Settings sheet and
    /// drops the session's toast, so nothing sits on top of the
    /// unlock screen.
    #[gpui::test]
    fn lock_closes_settings_and_overlays(cx: &mut TestAppContext) {
        use std::sync::Arc;
        use vault_core::{KdfParams, SecretString};
        use vault_sync::{NoopHooks, SyncedVault};

        let dir = tempfile::tempdir().unwrap();
        let vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, _| s.install_unlocked_for_tests(vault));
        vcx.run_until_parked();

        vcx.simulate_keystrokes("cmd-,");
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| {
            s.show_toast("Copied", cx);
        });
        assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));

        vcx.simulate_keystrokes("cmd-l");
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.screen, Screen::Unlock);
            assert!(!s.settings_open);
            assert!(s.toast.is_none());
        });
        assert!(
            !vcx.update(|window, cx| window.has_active_dialog(cx)),
            "no Settings dialog over the unlock card"
        );
    }

    /// Drives every settings tab, the restore and export confirms, and the detail-column
    /// sync banners on a real unlocked vault, checking nothing panics while rendering.
    #[gpui::test]
    fn sync_settings_tabs_and_banners_render(cx: &mut TestAppContext) {
        use std::sync::Arc;
        use vault_core::{Item, ItemKind, KdfParams, SecretString};
        use vault_sync::{NoopHooks, SyncedVault};

        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        vault
            .edit(|v| v.insert(Item::new(ItemKind::Login, "GitHub", device, 1), 1))
            .unwrap();
        vault.save().unwrap();
        vault.backup_now().unwrap();

        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, _| s.install_unlocked_for_tests(vault));
        vcx.run_until_parked();

        // Banners in the detail column, with an item and while editing.
        state.update(&mut vcx, |s, cx| {
            s.sync.corrupt = true;
            s.sync.waiting_for_cloud = true;
            s.sync.key_mismatch = true;
            s.sync.key_mismatch_error = Some("Wrong password. Try again.".into());
            cx.notify();
        });
        vcx.run_until_parked();
        vcx.simulate_keystrokes("cmd-e");
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| {
            if let Some(b) = s.edit_buffer_mut() {
                b.remote_title = true;
                b.remote_fields = b.keys.clone();
            }
            cx.notify();
        });
        vcx.run_until_parked();
        vcx.simulate_keystrokes("escape");

        // Every tab, with the vault unlocked.
        vcx.simulate_keystrokes("cmd-,");
        for tab in 0..5 {
            state.update(&mut vcx, |s, cx| {
                s.settings_tab = tab;
                cx.notify();
            });
            vcx.run_until_parked();
        }
        assert!(state.read_with(&vcx, |s, _| !s.sync.backups.is_empty()));

        // Restore: confirm step, then password step.
        let backup = state.read_with(&vcx, |s, _| s.sync.backups[0].path.clone());
        state.update(&mut vcx, |s, cx| s.request_restore(backup, cx));
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| s.confirm_restore(cx));
        vcx.run_until_parked();
        assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));

        // File > Export... jumps to the Import / Export tab with the red confirm.
        state.update(&mut vcx, |s, cx| s.cancel_restore(cx));
        vcx.dispatch_action(actions::Export);
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.settings_tab, crate::state::TRANSFER_TAB);
            assert!(s.sync.export_confirm);
        });

        // Locked: the sync tab still renders (Back up now works locked), restore is off.
        state.update(&mut vcx, |s, cx| {
            s.lock(cx);
            s.open_settings(true, cx);
            s.settings_tab = crate::state::SYNC_TAB;
            cx.notify();
        });
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| {
            s.settings_tab = crate::state::TRANSFER_TAB;
            cx.notify();
        });
        vcx.run_until_parked();
    }

    /// Security tab: the Touch ID row, KDF measurement on open, each inline form,
    /// the Advanced disclosure, a reduce-motion unlock, and the locked state.
    #[gpui::test]
    fn security_tab_renders_and_measures(cx: &mut TestAppContext) {
        use std::sync::Arc;
        use vault_core::{KdfParams, SecretString};
        use vault_sync::{NoopHooks, SyncedVault};

        use crate::state::{SECURITY_TAB, SecurityForm};

        let dir = tempfile::tempdir().unwrap();
        let vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        state.update(&mut vcx, |s, cx| {
            s.set_reduce_motion(true, cx);
            s.install_unlocked_for_tests(vault);
            s.settings_tab = SECURITY_TAB;
            s.open_settings(true, cx);
        });
        vcx.run_until_parked();
        assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));
        assert!(
            state.read_with(&vcx, |s, _| s.kdf_seconds().is_some()),
            "showing the tab measures the KDF"
        );

        for form in [
            Some(SecurityForm::ChangePassword),
            Some(SecurityForm::Recalibrate),
            None,
        ] {
            state.update(&mut vcx, |s, cx| s.set_security_form(form, cx));
            vcx.run_until_parked();
        }
        state.update(&mut vcx, |s, cx| {
            s.toggle_security_advanced(cx);
            s.set_security_form(Some(SecurityForm::RotateKey), cx);
            s.security.error = Some("The master password is wrong.".into());
            cx.notify();
        });
        vcx.run_until_parked();
        // Collapsing Advanced closes the rotate confirm.
        state.update(&mut vcx, |s, cx| s.toggle_security_advanced(cx));
        state.read_with(&vcx, |s, _| assert!(s.security.form.is_none()));
        // A wrong rotate password from the form surfaces inline.
        state.update(&mut vcx, |s, cx| {
            s.toggle_security_advanced(cx);
            s.set_security_form(Some(SecurityForm::RotateKey), cx);
            s.rotate_key(SecretString::new("nope".into()), cx);
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(
                s.security.error.as_deref(),
                Some("The master password is wrong.")
            );
            assert!(s.busy.is_none());
        });

        // Locking closes the forms; the tab still renders.
        state.update(&mut vcx, |s, cx| {
            s.lock(cx);
            s.open_settings(true, cx);
            s.settings_tab = SECURITY_TAB;
            cx.notify();
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.security.form.is_none());
            assert!(!s.security.advanced_open);
        });
    }

    /// Unlock screen with Touch ID: opening the vault starts Touch ID by itself, a lock
    /// shows the button (no automatic prompt), and a policy denial shows the hint instead.
    #[gpui::test]
    fn unlock_screen_offers_touch_id(cx: &mut TestAppContext) {
        use std::sync::Arc;
        use vault_core::{KdfParams, SecretString};
        use vault_sync::{NoopHooks, SyncedVault};

        use crate::biometric::fake::{Call, FakeBiometrics};
        use crate::state::{Screen, TouchDenied};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.vault");
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
        let bio = FakeBiometrics::new();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        let b: Arc<dyn crate::biometric::Biometrics> = bio.clone();
        state.update(&mut vcx, |s, cx| {
            s.set_biometrics(b);
            s.open_vault(path.clone(), cx);
        });
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| {
            s.unlock(SecretString::new("pw".into()), cx)
        });
        vcx.run_until_parked();
        state.update(&mut vcx, |s, cx| s.enable_touch_id(cx));
        vcx.run_until_parked();
        assert!(state.read_with(&vcx, |s, _| s.touch_enabled()));

        // Reopen: the unlock screen appears and Touch ID runs at once.
        state.update(&mut vcx, |s, cx| {
            s.close_vault(cx);
            s.open_vault(path.clone(), cx);
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.screen, Screen::Main, "auto Touch ID unlocked");
            assert!(s.unlocked_with_password_at.is_none());
        });
        let prompts = || {
            bio.calls()
                .iter()
                .filter(|c| matches!(c, Call::Unlock(..)))
                .count()
        };
        assert_eq!(prompts(), 1);

        // Lock: the button renders, nothing prompts until the window is activated.
        state.update(&mut vcx, |s, cx| s.lock(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.screen, Screen::Unlock);
            assert_eq!(s.touch_policy(), Ok(()));
        });
        assert_eq!(prompts(), 1);

        // Policy denial: the hint replaces the button.
        state.update(&mut vcx, |s, cx| {
            s.boot_time = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
            cx.notify();
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(s.touch_policy(), Err(TouchDenied::Rebooted));
        });
    }

    /// Appearance and text size apply live; empty states and the onboarding card render.
    #[gpui::test]
    fn appearance_text_size_and_empty_states(cx: &mut TestAppContext) {
        use gpui_component::{Theme, ThemeMode};
        use std::sync::Arc;
        use vault_core::{Item, ItemKind, KdfParams, SecretString};
        use vault_sync::{NoopHooks, SyncedVault};

        use crate::screens::{detail_placeholder, list_placeholder};
        use crate::state::{Appearance, TextSize};

        let dir = tempfile::tempdir().unwrap();
        let vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let window = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let mut vcx = VisualTestContext::from_window(window.into(), cx);

        // Empty vault after creation: onboarding card in the detail column.
        state.update(&mut vcx, |s, _| {
            s.install_unlocked_for_tests(vault);
            s.show_onboarding = true;
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.onboarding_visible());
            assert_eq!(list_placeholder(s), Some("This vault is empty"));
            assert_eq!(detail_placeholder(s), Some("Your vault is ready"));
        });
        state.update(&mut vcx, |s, cx| s.dismiss_onboarding(cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert!(s.settings.onboarding_dismissed);
            assert!(!s.onboarding_visible());
        });

        // Items but no selection: "Select an item"; a query with no hits: "No results".
        state.update(&mut vcx, |s, cx| {
            let device = s.device_id();
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.insert(Item::new(ItemKind::Login, "GitHub", device, 1), 1))
                .unwrap();
            s.vault_changed();
            s.selection = None;
            cx.notify();
        });
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(list_placeholder(s), None);
            assert_eq!(detail_placeholder(s), Some("Select an item"));
        });
        state.update(&mut vcx, |s, cx| s.set_query("zzz".into(), cx));
        vcx.run_until_parked();
        state.read_with(&vcx, |s, _| {
            assert_eq!(list_placeholder(s), Some("No results"));
        });

        // Dark override and the largest text step apply to the theme and the window rem.
        state.update(&mut vcx, |s, cx| {
            s.update_settings(cx, |st| {
                st.appearance = Appearance::Dark;
                st.text_size = TextSize::Larger;
            })
        });
        vcx.run_until_parked();
        vcx.update(|window, cx| {
            let theme = Theme::global(cx);
            assert_eq!(theme.mode, ThemeMode::Dark);
            assert!((theme.font_size.as_f32() - 13. * 1.3).abs() < 0.01);
            assert!((window.rem_size().as_f32() - 16. * 1.3).abs() < 0.01);
        });
        state.update(&mut vcx, |s, cx| {
            s.update_settings(cx, |st| {
                st.appearance = Appearance::Light;
                st.text_size = TextSize::Default;
            })
        });
        vcx.run_until_parked();
        vcx.update(|window, cx| {
            assert_eq!(Theme::global(cx).mode, ThemeMode::Light);
            assert!((window.rem_size().as_f32() - 16.).abs() < 0.01);
        });
        // The General tab renders (login item row hidden off-bundle).
        state.update(&mut vcx, |s, cx| {
            s.settings_tab = 0;
            s.open_settings(true, cx);
        });
        vcx.run_until_parked();
        assert_eq!(
            state.read_with(&vcx, |s, _| s.login_row()),
            crate::state::LoginRow::Hidden
        );
    }

    /// Item shortcuts pressed while the backup viewer is the active window must not touch
    /// the live vault; from the main window they work as usual.
    #[gpui::test]
    fn item_shortcuts_are_scoped_to_the_main_window(cx: &mut TestAppContext) {
        use std::sync::Arc;
        use vault_core::{Item, ItemKind, KdfParams, SecretString};
        use vault_sync::{NoopHooks, SyncedVault};

        let dir = tempfile::tempdir().unwrap();
        let mut vault = SyncedVault::create(
            &dir.path().join("t.vault"),
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let id = vault
            .edit(|v| v.insert(Item::new(ItemKind::Login, "GitHub", device, 1), 1))
            .unwrap();
        vault.save().unwrap();
        let backup = vault.backup_now().unwrap();

        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::register(&state, cx);
        });
        let main = cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        });
        let main: gpui::AnyWindowHandle = main.into();
        cx.run_until_parked();
        state.update(cx, |s, cx| {
            s.install_unlocked_for_tests(vault);
            s.select(id, cx);
            s.open_backup(backup.clone(), cx);
        });
        cx.run_until_parked();
        let viewer = cx
            .update(|cx| cx.windows())
            .into_iter()
            .find(|w| w.window_id() != main.window_id())
            .expect("viewer window");
        let favorite = |cx: &mut TestAppContext| {
            state.read_with(cx, |s, _| s.selected_item().unwrap().favorite)
        };

        cx.update_window(viewer, |_, window, _| window.activate_window())
            .unwrap();
        cx.run_until_parked();
        cx.dispatch_action(viewer, actions::ToggleFavorite);
        cx.dispatch_action(viewer, actions::EditItem);
        cx.run_until_parked();
        assert!(
            !favorite(cx),
            "⌘D in the viewer must not touch the live vault"
        );
        assert!(!state.read_with(cx, |s, _| s.is_editing()), "nor ⌘E");

        cx.update_window(main, |_, window, _| window.activate_window())
            .unwrap();
        cx.run_until_parked();
        cx.dispatch_action(main, actions::ToggleFavorite);
        cx.run_until_parked();
        assert!(favorite(cx), "from the main window it works");
    }
}
