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

/// A root window with a fresh vault (password "pw") opened, locked.
fn root_with_vault(
    dir: &std::path::Path,
    cx: &mut TestAppContext,
) -> (Entity<AppState>, Entity<VaultRoot>, VisualTestContext) {
    use std::sync::Arc;
    use vault_core::{KdfParams, SecretString};
    use vault_sync::{NoopHooks, SyncedVault};

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
    let mut root = None;
    let window = cx.add_window(|window, cx| {
        theme::apply(window, cx);
        let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
        root = Some(view.clone());
        ui::main_root(view, window, cx)
    });
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    state.update(&mut vcx, |s, cx| s.open_vault(path, cx));
    vcx.run_until_parked();
    (state, root.unwrap(), vcx)
}

#[gpui::test]
fn password_unlock_focuses_search(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, root, mut vcx) = root_with_vault(dir.path(), cx);
    state.update(&mut vcx, |s, cx| {
        s.unlock(vault_core::SecretString::new("pw".into()), cx)
    });
    vcx.run_until_parked();
    assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Main);
    vcx.update(|window, cx| {
        let main = root.read(cx).main.clone();
        assert!(main.read(cx).search_focused(window, cx));
    });
}

/// The unlock screen is gone before the main screen fades in (05 §2.2, §2.3).
#[gpui::test]
fn unlock_finish_ends_before_the_crossfade(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, root, mut vcx) = root_with_vault(dir.path(), cx);
    let ms = Duration::from_millis(1);
    state.update(&mut vcx, |s, cx| {
        s.unlock_hold = crate::state::MIN_UNLOCK_HOLD;
        s.fake_work_time = 50 * ms;
        s.unlock(vault_core::SecretString::new("pw".into()), cx)
    });
    vcx.executor().advance_clock(350 * ms - ms);
    assert!(vcx.debug_bounds("unlock-keyhole-flare").is_some());
    vcx.executor().advance_clock(ms);
    assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Main);
    for gone in [
        "unlock-card",
        "unlocking",
        "unlock-keyhole-flare",
        "unlock-icon",
    ] {
        assert!(vcx.debug_bounds(gone).is_none(), "{gone} during the fade");
    }
    vcx.update(|window, cx| {
        let main = root.read(cx).main.clone();
        assert!(
            main.read(cx).search_focused(window, cx),
            "focused during the fade"
        );
    });
}

/// No window toast is drawn over the unlock card while the finish plays; the unlock's
/// own toast (here the weak-KDF notice of a test-cost vault, L-20) shows with the items.
#[gpui::test]
fn unlock_toast_waits_for_the_finish(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _root, mut vcx) = root_with_vault(dir.path(), cx);
    let ms = Duration::from_millis(1);
    state.update(&mut vcx, |s, cx| {
        s.unlock_hold = crate::state::MIN_UNLOCK_HOLD;
        s.fake_work_time = 50 * ms;
        s.unlock(vault_core::SecretString::new("pw".into()), cx)
    });
    vcx.executor().advance_clock(350 * ms - ms);
    assert!(
        vcx.debug_bounds("unlock-keyhole-flare").is_some(),
        "finishing"
    );
    // Something else raises a toast mid-finish (a sync event, say).
    state.update(&mut vcx, |s, cx| s.show_toast("Vault updated", cx));
    vcx.run_until_parked();
    assert!(
        vcx.debug_bounds("window-toast").is_none(),
        "not on the card"
    );
    vcx.executor().advance_clock(ms);
    vcx.run_until_parked();
    assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Main);
    assert!(vcx.debug_bounds("window-toast").is_some(), "with the items");
    assert_eq!(
        state.read_with(&vcx, |s, _| s.toast.as_ref().map(|t| t.message.clone())),
        Some(crate::state::WEAK_KDF.into())
    );
}

#[gpui::test]
fn close_window_locks_before_closing_and_reopens_locked(cx: &mut TestAppContext) {
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
        cx.set_global(crate::RunningVault(state.clone()));
    });
    state.update(cx, |s, _| s.install_unlocked_for_tests(vault));
    let main = cx.add_window(|window, cx| {
        theme::apply(window, cx);
        let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
        Root::new(view, window, cx)
    });
    let main: gpui::AnyWindowHandle = main.into();
    cx.run_until_parked();
    assert_eq!(state.read_with(cx, |s, _| s.screen), Screen::Main);

    let closed = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = closed.clone();
    let checked = state.clone();
    let _closed_subscription = cx.update(|cx| {
        cx.on_window_closed(move |cx, id| {
            if id == main.window_id() {
                assert!(
                    checked.read(cx).locked,
                    "vault locked before the window closes"
                );
                observed.set(true);
            }
        })
    });
    cx.update_window(main, |_, window, _| window.activate_window())
        .unwrap();
    cx.simulate_keystrokes(main, "cmd-w");
    cx.run_until_parked();
    assert!(closed.get());
    assert!(cx.update(|cx| cx.windows().is_empty()));
    state.read_with(cx, |s, _| {
        assert!(s.locked);
        assert_eq!(s.screen, Screen::Unlock);
    });

    cx.update(crate::reopen_main_window);
    cx.run_until_parked();
    assert_eq!(cx.update(|cx| cx.windows().len()), 1);
    state.read_with(cx, |s, _| {
        assert!(s.locked);
        assert_eq!(s.screen, Screen::Unlock);
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

    // ⌘, does nothing on the choose-vault screen: Settings needs an unlocked vault.
    vcx.simulate_keystrokes("cmd-,");
    vcx.run_until_parked();
    assert!(!state.read_with(&vcx, |s, _| s.settings_open));
    assert!(!vcx.update(|window, cx| window.has_active_dialog(cx)));

    let dir = tempfile::tempdir().unwrap();
    let vault = vault_sync::SyncedVault::create(
        &dir.path().join("t.vault"),
        &vault_core::SecretString::new("pw".into()),
        vault_core::KdfParams::for_tests(),
        Uuid::new_v4(),
        std::sync::Arc::new(vault_sync::NoopHooks),
    )
    .unwrap();
    state.update(&mut vcx, |s, _| s.install_unlocked_for_tests(vault));
    vcx.run_until_parked();

    // Unlocked, ⌘, opens the dialog.
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
        s.refresh_backups();
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

/// The first `# ` heading of `docs/help.md`, read from disk at test time, so a broken
/// `include_str!` (wrong file, empty page) fails [`help_sheet_opens_while_locked_and_esc_closes_it`].
fn help_heading_on_disk() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/help.md");
    let page = std::fs::read_to_string(path).unwrap();
    let line = page.lines().find(|l| l.starts_with("# ")).unwrap();
    line[2..].trim().to_owned()
}

/// ⌘? on the unlock screen (locked) opens the Help sheet titled with the page's first
/// heading; Esc closes it and the state follows.
#[gpui::test]
fn help_sheet_opens_while_locked_and_esc_closes_it(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _root, mut vcx) = root_with_vault(dir.path(), cx);
    assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Unlock);

    vcx.simulate_keystrokes(actions::HELP_KEYS);
    vcx.run_until_parked();
    assert!(state.read_with(&vcx, |s, _| s.help_open));
    assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));
    // `debug_bounds` takes a static selector.
    let title: &'static str = format!("sheet-title {}", help_heading_on_disk()).leak();
    assert!(vcx.debug_bounds(title).is_some(), "{title} drawn");

    vcx.simulate_keystrokes("escape");
    vcx.run_until_parked();
    assert!(!vcx.update(|window, cx| window.has_active_dialog(cx)));
    assert!(!state.read_with(&vcx, |s, _| s.help_open));

    // The menu item's action takes the same path.
    vcx.dispatch_action(actions::ShowHelp);
    vcx.run_until_parked();
    assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));
}

/// Help over an item being edited: Esc closes the sheet only, the edit stays. Help
/// then replaces an open Settings sheet, and ⌘, replaces Help again.
#[gpui::test]
fn help_esc_keeps_the_edit_and_replaces_settings(cx: &mut TestAppContext) {
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
    let item = Item::new("GitHub", vault.device_id(), 1);
    let id = item.id;
    vault.edit(|v| v.insert(item, 1)).unwrap();
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
    vcx.update(|window, _| window.activate_window());
    state.update(&mut vcx, |s, _| s.install_unlocked_for_tests(vault));
    vcx.run_until_parked();
    let edit = |vcx: &mut VisualTestContext| {
        state.update(vcx, |s, cx| {
            s.select(id, cx);
            s.begin_edit(cx);
        });
        vcx.run_until_parked();
        vcx.dispatch_action(actions::FocusDetail);
        vcx.run_until_parked();
        assert!(state.read_with(vcx, |s, _| s.is_editing()));
    };
    // Without a sheet, Esc reaches the editor and cancels: the check below means something.
    edit(&mut vcx);
    vcx.simulate_keystrokes("escape");
    vcx.run_until_parked();
    assert!(!state.read_with(&vcx, |s, _| s.is_editing()));
    edit(&mut vcx);

    vcx.simulate_keystrokes(actions::HELP_KEYS);
    vcx.run_until_parked();
    assert!(vcx.update(|window, cx| window.has_active_dialog(cx)));
    vcx.simulate_keystrokes("escape");
    vcx.run_until_parked();
    assert!(!vcx.update(|window, cx| window.has_active_dialog(cx)));
    assert!(!state.read_with(&vcx, |s, _| s.help_open));
    assert!(
        state.read_with(&vcx, |s, _| s.is_editing()),
        "Esc closed the sheet, not the edit"
    );

    vcx.simulate_keystrokes("cmd-,");
    vcx.run_until_parked();
    vcx.simulate_keystrokes(actions::HELP_KEYS);
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| assert!(s.help_open && !s.settings_open));
    // `debug_bounds` takes a static selector.
    let help: &'static str = format!("sheet-title {}", help_heading_on_disk()).leak();
    assert!(vcx.debug_bounds(help).is_some(), "Help replaced Settings");
    assert!(vcx.debug_bounds("sheet-title Settings").is_none());

    vcx.simulate_keystrokes("cmd-,");
    vcx.run_until_parked();
    state.read_with(&vcx, |s, _| assert!(!s.help_open && s.settings_open));
    assert!(vcx.debug_bounds("sheet-title Settings").is_some());
    assert!(vcx.debug_bounds(help).is_none());
}

/// The placeholder toast is gone from every source file of the crate.
#[test]
fn help_placeholder_toast_is_gone() {
    let needle = concat!("Help is not ", "available yet");
    let mut dirs = vec![std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src"
    ))];
    let mut files = 0;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files += 1;
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(!text.contains(needle), "{}", path.display());
            }
        }
    }
    assert!(files > 10);
}

/// Sidebar vibrancy (05 §5) render checks: a fresh frame.
fn frame(vcx: &mut VisualTestContext) {
    vcx.update(|window, _| window.refresh());
    vcx.run_until_parked();
}

/// Whether a solid quad in `color` is painted within 1 px of `area`.
fn fill_at(
    area: gpui::Bounds<gpui::Pixels>,
    color: gpui::Hsla,
    vcx: &mut VisualTestContext,
) -> bool {
    vcx.update(|window, _| {
        let scaled = area.scale(window.scale_factor());
        let near = |a: gpui::ScaledPixels, b: gpui::ScaledPixels| (a.0 - b.0).abs() < 1.;
        window.painted_quads().iter().any(|q| {
            near(q.bounds.origin.x, scaled.origin.x)
                && near(q.bounds.origin.y, scaled.origin.y)
                && near(q.bounds.size.width, scaled.size.width)
                && near(q.bounds.size.height, scaled.size.height)
                && q.background.as_solid() == Some(color)
        })
    })
}

fn whole_window(vcx: &mut VisualTestContext) -> gpui::Bounds<gpui::Pixels> {
    vcx.update(|window, _| gpui::Bounds::new(gpui::Point::default(), window.viewport_size()))
}

fn background(vcx: &mut VisualTestContext) -> gpui::Hsla {
    vcx.update(|_, cx| cx.theme().background)
}

fn unlock(state: &Entity<AppState>, vcx: &mut VisualTestContext) {
    state.update(vcx, |s, cx| {
        s.unlock(vault_core::SecretString::new("pw".into()), cx)
    });
    vcx.run_until_parked();
    assert_eq!(state.read_with(vcx, |s, _| s.screen), Screen::Main);
}

/// Under Reduce Motion there is no crossfade, so the fade is finished at once and the
/// root schedules no per-frame redraw for its underlay.
#[gpui::test]
fn reduce_motion_unlock_needs_no_fade_underlay(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, root, mut vcx) = root_with_vault(dir.path(), cx);
    state.update(&mut vcx, |s, cx| s.set_reduce_motion(true, cx));
    unlock(&state, &mut vcx);
    for _ in 0..3 {
        frame(&mut vcx);
    }
    let count = state.read_with(&vcx, |s, _| s.unlock_count);
    root.read_with(&vcx, |r, _| {
        assert_eq!(r.fade.0, count);
        assert!(r.fade.1.get(), "fade marked finished under Reduce Motion");
    });
}

/// The root leaves the window unfilled on the main screen (the crossfade underlay is
/// gone once the fade ends) and fills it again on the unlock screen after a lock.
#[gpui::test]
fn root_fill_is_skipped_on_main_and_back_after_lock(cx: &mut TestAppContext) {
    root_fill_check(cx);
}

/// [`root_fill_is_skipped_on_main_and_back_after_lock`] in dark mode.
#[gpui::test]
fn dark_root_fill_is_skipped_on_main_and_back_after_lock(cx: &mut TestAppContext) {
    cx.update(|cx| {
        cx.set_global(theme::ThemePrefs {
            appearance: crate::state::Appearance::Dark,
            scale: 1.0,
        })
    });
    root_fill_check(cx);
    cx.update(|cx| assert!(cx.theme().is_dark()));
}

fn root_fill_check(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, root, mut vcx) = root_with_vault(dir.path(), cx);
    frame(&mut vcx);
    let (window, bg) = (whole_window(&mut vcx), background(&mut vcx));
    assert!(fill_at(window, bg, &mut vcx), "unlock screen is filled");

    unlock(&state, &mut vcx);
    // The crossfade runs on real time.
    std::thread::sleep(CROSSFADE + Duration::from_millis(50));
    for _ in 0..3 {
        frame(&mut vcx);
    }
    assert!(root.read_with(&vcx, |r, _| r.fade.1.get()), "fade finished");
    assert!(
        !fill_at(window, bg, &mut vcx),
        "main screen has no window fill"
    );

    state.update(&mut vcx, |s, cx| s.lock(cx));
    vcx.run_until_parked();
    frame(&mut vcx);
    assert_eq!(state.read_with(&vcx, |s, _| s.screen), Screen::Unlock);
    assert!(
        fill_at(window, bg, &mut vcx),
        "unlock screen is filled again"
    );
}

/// In light mode the list and detail columns paint the opaque background themselves.
#[gpui::test]
fn light_list_and_detail_columns_paint_opaque_background(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, mut vcx) = root_with_vault(dir.path(), cx);
    state.update(&mut vcx, |s, cx| s.set_reduce_motion(true, cx));
    unlock(&state, &mut vcx);
    frame(&mut vcx);
    assert!(!vcx.update(|_, cx| cx.theme().is_dark()), "light mode");
    let bg = background(&mut vcx);
    assert_eq!(bg.a, 1.);
    for column in ["list-slot", "detail-slot"] {
        let area = vcx.debug_bounds(column).expect(column);
        assert!(
            fill_at(area, bg, &mut vcx),
            "{column} paints the background"
        );
    }
}

/// ⌘O (`OpenVault`) on the choose screen: from Create it goes back to Home and shows no
/// file panel; from Home it shows the file panel, as the "Open existing vault…" link.
#[gpui::test]
fn open_vault_on_the_choose_screen_follows_its_step(cx: &mut TestAppContext) {
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
    let home = |vcx: &mut VisualTestContext| vcx.debug_bounds("choose-card").is_some();
    assert!(home(&mut vcx));

    // File > New Vault, then ⌘O: back to Home, no panel.
    vcx.dispatch_action(actions::NewVault);
    vcx.run_until_parked();
    assert!(!home(&mut vcx), "the create form");
    vcx.simulate_keystrokes("cmd-o");
    vcx.run_until_parked();
    assert!(home(&mut vcx));
    assert!(!vcx.did_prompt_for_paths(), "Create: back to Home only");

    // ⌘O on Home: the file panel, and the card stays.
    vcx.simulate_keystrokes("cmd-o");
    vcx.run_until_parked();
    assert!(vcx.did_prompt_for_paths(), "Home: the file panel");
    assert!(home(&mut vcx));
    vcx.simulate_path_prompt_response(|_| None);
    vcx.run_until_parked();
}

/// File ▸ Open Vault… with the main window closed stores the plain Home request, not the
/// file-panel one: the next main window shows the welcome card and no panel.
#[gpui::test]
fn open_vault_without_a_main_window_shows_no_panel_later(cx: &mut TestAppContext) {
    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    cx.update(|cx| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        actions::register(&state, cx);
    });
    let open = |cx: &mut TestAppContext| {
        cx.add_window(|window, cx| {
            theme::apply(window, cx);
            let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
            Root::new(view, window, cx)
        })
    };
    // A main window that was open once and closed: the global outlives it.
    let first = open(cx);
    cx.run_until_parked();
    first
        .update(cx, |_, window, _| window.remove_window())
        .unwrap();
    cx.run_until_parked();
    assert!(cx.update(|cx| actions::main_window(cx).is_none()));

    cx.update(|cx| cx.dispatch_action(&actions::OpenVault));
    cx.run_until_parked();
    state.read_with(cx, |s, _| {
        assert_eq!(s.choose_request, Some(crate::state::ChooseIntent::Home));
    });

    let second = open(cx);
    let mut vcx = VisualTestContext::from_window(second.into(), cx);
    vcx.run_until_parked();
    assert!(vcx.debug_bounds("choose-card").is_some());
    assert!(!vcx.did_prompt_for_paths(), "no panel on the next window");
}

/// An unlocked main window (auto-lock 5 minutes, lock-on-sleep off) with one item whose
/// password is "hunter2", selected; the fake pasteboard is returned.
fn sleepy_window(
    dir: &std::path::Path,
    cx: &mut TestAppContext,
) -> (
    Entity<AppState>,
    Uuid,
    crate::clipboard::fake::FakePasteboard,
    VisualTestContext,
) {
    use std::sync::Arc;
    use vault_core::{Field, FieldKind, Item, KdfParams, SecretString};
    use vault_sync::{NoopHooks, SyncedVault};

    let mut vault = SyncedVault::create(
        &dir.join("t.vault"),
        &SecretString::new("pw".into()),
        KdfParams::for_tests(),
        Uuid::new_v4(),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let device = vault.device_id();
    let mut item = Item::new("GitHub", device, 1);
    item.fields = vec![
        Field::new(
            "username",
            FieldKind::Text,
            SecretString::new("chris".into()),
            1,
        ),
        Field::new(
            "password",
            FieldKind::Password,
            SecretString::new("hunter2".into()),
            1,
        ),
    ];
    let id = vault.edit(|v| v.insert(item, 1)).unwrap();
    vault.save().unwrap();

    let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
    cx.update(|cx| {
        gpui_component::init(cx);
        actions::bind_keys(cx);
        actions::register(&state, cx);
    });
    let window = cx.add_window(|window, cx| {
        theme::apply(window, cx);
        let view = cx.new(|cx| VaultRoot::new(state.clone(), None, window, cx));
        ui::main_root(view, window, cx)
    });
    let mut vcx = VisualTestContext::from_window(window.into(), cx);
    let board = crate::clipboard::fake::FakePasteboard::default();
    state.update(&mut vcx, |s, cx| {
        s.install_unlocked_for_tests(vault);
        s.set_pasteboard(Box::new(board.clone()));
        s.settings.auto_lock_minutes = Some(5);
        s.settings.lock_on_sleep = false;
        s.select(id, cx);
        // The unlock's weak-KDF notice (test KDF costs) is not under test here.
        s.toast = None;
    });
    vcx.run_until_parked();
    (state, id, board, vcx)
}

fn sleep_for(state: &Entity<AppState>, minutes: u64, vcx: &mut VisualTestContext) {
    state.update(vcx, |s, _| {
        s.clock.sleep(std::time::Duration::from_secs(minutes * 60));
    });
}

/// A shortcut after a sleep past the idle limit locks before gpui matches its binding
/// (the keystroke interceptor), so ⌘⇧C copies nothing (L-13). Without the sleep the same
/// shortcut copies, which shows the gate is what stopped it.
#[gpui::test]
fn shortcut_after_a_long_sleep_locks_and_copies_nothing(cx: &mut TestAppContext) {
    // Actions gpui dispatched for a keystroke (observers run after dispatch, and not at
    // all when an interceptor stopped the keystroke).
    let dispatched = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
    let _observer = cx.update(|cx| {
        let dispatched = dispatched.clone();
        cx.observe_keystrokes(move |event, _, _| {
            if let Some(action) = &event.action {
                dispatched.borrow_mut().push(action.name().to_owned());
            }
        })
    });
    let dir = tempfile::tempdir().unwrap();
    let (state, _, board, mut vcx) = sleepy_window(dir.path(), cx);
    vcx.simulate_keystrokes("cmd-shift-c");
    vcx.run_until_parked();
    assert_eq!(
        board.contents().as_deref(),
        Some("hunter2"),
        "awake: copies"
    );
    assert_eq!(dispatched.borrow().len(), 1, "awake: the action ran");
    dispatched.borrow_mut().clear();
    state.update(&mut vcx, |s, cx| s.lock(cx));

    let dir = tempfile::tempdir().unwrap();
    let (state, _, board, mut vcx) = sleepy_window(dir.path(), cx);
    sleep_for(&state, 10, &mut vcx);
    vcx.simulate_keystrokes("cmd-shift-c");
    vcx.run_until_parked();
    assert!(
        state.read_with(&vcx, |s, _| s.locked),
        "locked by the key press"
    );
    assert_eq!(board.contents(), None, "nothing copied");
    assert!(board.clear_calls().is_empty(), "nothing was ever written");
    assert!(dispatched.borrow().is_empty(), "stopped before the binding");

    // ⌘L is let through when the gate locks: its own action still runs.
    state.update(&mut vcx, |s, cx| s.lock(cx));
    let dir = tempfile::tempdir().unwrap();
    let (state, _, _, mut vcx) = sleepy_window(dir.path(), cx);
    sleep_for(&state, 10, &mut vcx);
    vcx.simulate_keystrokes("cmd-l");
    vcx.run_until_parked();
    assert!(state.read_with(&vcx, |s, _| s.locked));
    assert_eq!(dispatched.borrow().len(), 1, "⌘L dispatched");
}

/// A click in the main window after a sleep past the idle limit locks in the capture
/// phase and never reaches the field it hit (L-13).
#[gpui::test]
fn click_after_a_long_sleep_locks_and_copies_nothing(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, board, mut vcx) = sleepy_window(dir.path(), cx);
    let password = vcx
        .debug_bounds("field-value 1")
        .expect("password row")
        .center();
    sleep_for(&state, 10, &mut vcx);
    vcx.simulate_click(password, gpui::Modifiers::none());
    vcx.run_until_parked();
    assert!(state.read_with(&vcx, |s, _| s.locked));
    assert_eq!(board.contents(), None, "nothing copied");
}

/// The same gate on a pinned item window: its own root, not the main one (L-13).
#[gpui::test]
fn item_window_click_after_a_long_sleep_locks_and_copies_nothing(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, id, board, mut vcx) = sleepy_window(dir.path(), cx);
    let item = vcx
        .update(|_, cx| crate::screens::open_item_window(state.clone(), id, cx))
        .unwrap();
    vcx.run_until_parked();
    let mut item = VisualTestContext::from_window(item, &vcx);
    item.run_until_parked();
    let password = item
        .debug_bounds("field-value 1")
        .expect("password row")
        .center();
    // Control: awake, the click copies.
    item.simulate_click(password, gpui::Modifiers::none());
    item.run_until_parked();
    assert_eq!(board.contents().as_deref(), Some("hunter2"));
    board.set("from another app");

    sleep_for(&state, 10, &mut item);
    let windows = vcx.update(|_, cx| cx.windows().len());
    // Mouse-down only: the lock closes the item window, so no mouse-up can follow.
    item.simulate_event(gpui::MouseDownEvent {
        position: password,
        modifiers: gpui::Modifiers::none(),
        button: gpui::MouseButton::Left,
        click_count: 1,
        first_mouse: false,
    });
    vcx.run_until_parked();
    assert!(state.read_with(&vcx, |s, _| s.locked));
    assert_eq!(
        vcx.update(|_, cx| cx.windows().len()),
        windows - 1,
        "closed"
    );
    assert_eq!(board.contents().as_deref(), Some("from another app"));
}

/// ⌘L and ⌘Q pass the gate; everything else stops there once it has locked.
#[test]
fn only_lock_and_quit_pass_the_gate() {
    let k = |s: &'static str| gpui::Keystroke::parse(s).unwrap();
    assert!(autolock::passes_lock(&k("cmd-l")));
    assert!(autolock::passes_lock(&k("cmd-q")));
    for other in ["cmd-shift-c", "cmd-shift-r", "cmd-c", "l", "cmd-shift-l"] {
        assert!(!autolock::passes_lock(&k(other)), "{other}");
    }
}
