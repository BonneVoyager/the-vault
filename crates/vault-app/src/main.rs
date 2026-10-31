//! vault: native macOS password manager UI.

mod actions;
mod assets;
mod audit;
mod autolock;
mod biometric;
mod clipboard;
mod cloud;
mod cursor_audit;
mod icon;
mod icon_image;
mod listing;
mod persist;
mod root;
mod screens;
mod state;
mod templates;
mod text;
mod theme;
mod ui;

use gpui::{App, AppContext as _, Entity, QuitMode};

use crate::root::VaultRoot;
use crate::state::{AppState, Sort};

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

    gpui_platform::application()
        .with_quit_mode(QuitMode::LastWindowClosed)
        .with_assets(assets::AppAssets)
        .run(|cx: &mut App| {
            gpui_component::init(cx);
            actions::bind_keys(cx);
            actions::set_menus(Sort::default(), cx);

            let settings = persist::load_settings();
            theme::set_prefs(&settings, cx);
            let state = cx.new(|_| {
                AppState::new(vault_macos::device_id(), persist::load_recent(), true)
                    .with_settings(settings)
            });
            register_actions(&state, cx);

            let restore = persist::load_window_state();
            let opened = ui::open_main_window(restore, cx, |window, cx| {
                theme::apply(window, cx);
                cx.new(|cx| VaultRoot::new(state.clone(), restore, window, cx))
            });
            if let Err(err) = opened {
                eprintln!("vault: failed to open main window: {err:#}");
                cx.quit();
                return;
            }

            // A remembered vault skips the choose screen (05 §2.1).
            state.update(cx, |s, cx| {
                if let Some(path) = s.recent_vaults.first().cloned() {
                    s.open_vault(path, cx);
                }
            });
            cx.activate(true);
        });
}
