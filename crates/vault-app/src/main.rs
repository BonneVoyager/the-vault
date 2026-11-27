//! vault: native macOS password manager UI.

mod actions;
mod assets;
mod audit;
mod autolock;
mod biometric;
mod bounded_read;
mod clipboard;
mod clock;
mod cloud;
mod cursor_audit;
mod icon;
mod icon_image;
mod listing;
mod persist;
mod root;
mod screens;
mod state;
mod status_item;
mod templates;
mod text;
mod theme;
mod ui;

use gpui::{App, AppContext as _, Entity, QuitMode};

use crate::root::VaultRoot;
use crate::state::{AppState, Sort};

/// The vault session outlives its main window so a Dock click can restore the UI.
struct RunningVault(Entity<AppState>);

impl gpui::Global for RunningVault {}

fn reopen_main_window(cx: &mut App) {
    let Some(state) = cx
        .try_global::<RunningVault>()
        .map(|running| running.0.clone())
    else {
        return;
    };
    // Dock icon off: re-assert Accessory before activating (04 §5b). The bundle is
    // LSUIElement, so this is belt and braces against Launch Services re-registering
    // the app as foreground when it is opened again from Finder; idempotent.
    if !state.read(cx).settings.show_in_dock {
        state::set_dock_icon(false, cx);
    }
    if let Some(handle) = actions::main_window(cx) {
        cx.activate(true);
        handle
            .update(cx, |_, window, _| window.activate_window())
            .ok();
        return;
    }

    let restore = persist::load_window_state();
    let sidebar_visible = state.read(cx).sidebar_visible();
    match ui::open_main_window(restore, sidebar_visible, cx, |window, cx| {
        theme::apply(window, cx);
        cx.new(|cx| VaultRoot::new(state.clone(), restore, window, cx))
    }) {
        Ok(handle) => {
            cx.activate(true);
            handle
                .update(cx, |_, window, _| window.activate_window())
                .ok();
            if !sidebar_visible {
                ui::apply_main_min_size(false);
            }
        }
        Err(err) => eprintln!("vault: failed to reopen main window: {err:#}"),
    }
}

/// Global action handlers plus the quit hook.
fn register_actions(state: &Entity<AppState>, cx: &mut App) {
    actions::register(state, cx);
    // Covers every quit path (⌘Q, Dock, logout): save pending edits and drop the keys.
    let s = state.clone();
    cx.on_app_quit(move |cx| {
        s.update(cx, |s, cx| {
            s.wait_for_background();
            s.lock(cx);
        });
        async {}
    })
    .detach();
}

fn main() {
    // Log output goes to stderr only and must never include secrets (passwords, keys,
    // TOTP secrets, item contents). Default level `warn`; RUST_LOG overrides.
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("warn"));

    let app = gpui_platform::application()
        .with_quit_mode(QuitMode::Explicit)
        .with_assets(assets::AppAssets);
    app.on_reopen(reopen_main_window);
    app.run(|cx: &mut App| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        let settings = persist::load_settings();
        // Read while gpui runs this closure inside applicationDidFinishLaunching, the
        // only time the current Apple Event is the launch event (04 §5d).
        let background = status_item::start_in_background(
            vault_macos::launched_as_login_item(),
            settings.show_in_dock,
        );
        actions::set_menus(Sort::default(), !settings.sidebar_hidden, cx);
        theme::set_prefs(&settings, cx);
        // Before the first window: the bundle is LSUIElement, so the Dock icon only
        // appears because this sets Regular (04 §5b). Activation follows the window.
        state::set_dock_icon(settings.show_in_dock, cx);
        let state = cx.new(|_| {
            AppState::new(vault_macos::device_id(), persist::load_recent(), true)
                .with_settings(settings)
        });
        cx.set_global(RunningVault(state.clone()));
        register_actions(&state, cx);

        // Login launch with the Dock icon off: no window and no activation; the padlock,
        // Finder or Spotlight opens it through `reopen_main_window` (05 §2.5).
        let sidebar_visible = state.read(cx).sidebar_visible();
        if !background {
            let restore = persist::load_window_state();
            let opened = ui::open_main_window(restore, sidebar_visible, cx, |window, cx| {
                theme::apply(window, cx);
                cx.new(|cx| VaultRoot::new(state.clone(), restore, window, cx))
            });
            if let Err(err) = opened {
                eprintln!("vault: failed to open main window: {err:#}");
                cx.quit();
                return;
            }
        }

        // A remembered vault skips the choose screen (05 §2.1).
        state.update(cx, |s, cx| {
            if let Some(path) = s.recent_vaults.first().cloned() {
                s.open_vault(path, cx);
            }
        });
        // Dock icon off: the menu bar item is the way back (05 §2.5, 04 §5c).
        status_item::install(
            &state,
            status_item::macos_installer(),
            reopen_main_window,
            cx,
        );
        // The menu bar follows the state, window or not (05 §3).
        actions::follow_state_with_menus(&state, cx);
        if background {
            return;
        }
        cx.activate(true);
        // The window opened with this minimum already; re-applied through the one
        // hook (best effort: the window may not be key yet).
        if !sidebar_visible {
            ui::apply_main_min_size(false);
        }
    });
}
