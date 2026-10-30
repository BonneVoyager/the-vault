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
fn password_unlock_focuses_search(cx: &mut TestAppContext) {
    use std::sync::Arc;
    use vault_core::{KdfParams, SecretString};
    use vault_sync::{NoopHooks, SyncedVault};

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
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    cx.update(|cx| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        actions::register(&state, cx);
    });
    let mut root = None;
    let window = cx.add_window(|window, cx| {
        theme::apply(window, cx);
        let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
        root = Some(view.clone());
        Root::new(view, window, cx)
    });
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    state.update(&mut vcx, |s, cx| s.open_vault(path, cx));
    vcx.run_until_parked();
    state.update(&mut vcx, |s, cx| {
        s.unlock(SecretString::new("pw".into()), cx)
    });
    vcx.run_until_parked();
    assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Main);
    vcx.update(|window, cx| {
        let main = root.as_ref().unwrap().read(cx).main.clone();
        assert!(main.read(cx).search_focused(window, cx));
    });
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
    use vault_core::{Item, KdfParams, SecretString};
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
        .edit(|v| v.insert(Item::new("GitHub", device, 1), 1))
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
    use vault_core::{Item, KdfParams, SecretString};
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
            .edit(|v| v.insert(Item::new("GitHub", device, 1), 1))
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
    use vault_core::{Item, KdfParams, SecretString};
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
        .edit(|v| v.insert(Item::new("GitHub", device, 1), 1))
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
    let favorite =
        |cx: &mut TestAppContext| state.read_with(cx, |s, _| s.selected_item().unwrap().favorite);

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
