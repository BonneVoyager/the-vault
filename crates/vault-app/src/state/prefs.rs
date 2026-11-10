//! Settings ▸ General extras (specs/05-ui.md §2.5): launch at login and the first-run
//! tips card. Appearance and text size live in `Settings` and apply through `theme`.

use gpui::{ActivationPolicy, App, Context};
use vault_macos::LoginItemStatus;

use super::AppState;

/// How the "Launch at login" row renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginRow {
    /// Not running from an .app bundle (cargo run, tests), or unsupported.
    Hidden,
    Toggle(bool),
    /// Registered but blocked in System Settings ▸ Login Items: offer to open it.
    NeedsApproval,
}

/// `status` is `None` when not running from an app bundle.
pub fn login_row(status: Option<LoginItemStatus>) -> LoginRow {
    match status {
        None | Some(LoginItemStatus::Unavailable) => LoginRow::Hidden,
        Some(LoginItemStatus::Enabled) => LoginRow::Toggle(true),
        // NotFound: the service is not registered (yet), which reads as off.
        Some(LoginItemStatus::Disabled | LoginItemStatus::NotFound) => LoginRow::Toggle(false),
        Some(LoginItemStatus::RequiresApproval) => LoginRow::NeedsApproval,
    }
}

/// The activation policy for "Show Vault in Dock" (04 §5b): on = `Regular` (Dock icon
/// and menu bar), off = `Accessory` (menu bar padlock only).
pub fn dock_policy(show: bool) -> ActivationPolicy {
    if show {
        ActivationPolicy::Regular
    } else {
        ActivationPolicy::Accessory
    }
}

/// Shows or hides the Dock icon (and with it the menu bar), 04 §5b. Main thread only.
/// Goes through gpui, not AppKit directly, so gpui's cached policy agrees and is never
/// re-applied as `Regular` behind our back. The bundle is `LSUIElement`, so this call is
/// also what makes the Dock icon appear at launch when the setting is on.
/// At launch on its own: `main` activates the app afterwards anyway.
pub fn set_dock_icon(show: bool, cx: &mut App) {
    #[cfg(test)]
    tests::record_policy(dock_policy(show));
    cx.set_activation_policy(dock_policy(show));
}

/// [`set_dock_icon`] on toggling, then re-activates the app either way: back on, AppKit
/// needs it to draw the menu bar; off, a frontmost app switching to accessory can lose
/// its active state and let the Settings sheet slip behind other windows. With no
/// window (a background login start whose status item failed, 05 §2.5) it does not
/// activate: a windowless Vault is never brought to the front.
pub fn apply_dock_icon(show: bool, cx: &mut App) {
    set_dock_icon(show, cx);
    if !cx.windows().is_empty() {
        #[cfg(test)]
        tests::record_activation();
        cx.activate(true);
    }
}

impl AppState {
    /// Re-reads the login item status (on opening the settings sheet).
    pub(super) fn refresh_login_item(&mut self) {
        self.login_item =
            vault_macos::running_from_app_bundle().then(vault_macos::login_item_status);
    }

    pub fn login_row(&self) -> LoginRow {
        login_row(self.login_item)
    }

    pub fn set_launch_at_login(&mut self, on: bool, cx: &mut Context<Self>) {
        // The row is hidden off-bundle; never register a bare binary as a login item.
        if !vault_macos::running_from_app_bundle() {
            return;
        }
        if let Err(e) = vault_macos::set_launch_at_login(on) {
            self.show_toast(format!("Could not change Launch at login: {e}"), cx);
        }
        self.refresh_login_item();
        cx.notify();
    }

    /// The tips card shows after creating a vault until dismissed once.
    pub fn onboarding_visible(&self) -> bool {
        self.show_onboarding && !self.settings.onboarding_dismissed
    }

    pub fn dismiss_onboarding(&mut self, cx: &mut Context<Self>) {
        self.show_onboarding = false;
        self.update_settings(cx, |s| s.onboarding_dismissed = true);
        cx.notify();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// Every policy [`set_dock_icon`] applied on this thread (gpui's test platform
        /// ignores `set_activation_policy` and has no getter).
        static APPLIED: RefCell<Vec<ActivationPolicy>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record_policy(policy: ActivationPolicy) {
        APPLIED.with(|a| a.borrow_mut().push(policy));
    }

    thread_local! {
        /// `cx.activate(true)` calls from [`apply_dock_icon`] (a no-op on the test platform).
        static ACTIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    pub(crate) fn record_activation() {
        ACTIVATIONS.with(|n| n.set(n.get() + 1));
    }

    /// Drains the activation count recorded on this thread.
    pub(crate) fn take_activations() -> usize {
        ACTIVATIONS.with(|n| n.replace(0))
    }

    /// Drains the policies recorded on this thread.
    pub(crate) fn take_applied_policies() -> Vec<ActivationPolicy> {
        APPLIED.with(|a| std::mem::take(&mut *a.borrow_mut()))
    }

    #[test]
    fn dock_policy_mapping() {
        assert_eq!(dock_policy(true), ActivationPolicy::Regular);
        assert_eq!(dock_policy(false), ActivationPolicy::Accessory);
    }

    /// The reopen handler (Finder / Dock / status item) re-asserts Accessory when the
    /// Dock icon is off and leaves the policy alone when it is on (04 §5b).
    #[gpui::test]
    fn reopen_reapplies_accessory_when_dock_off(cx: &mut gpui::TestAppContext) {
        use gpui::AppContext as _;
        let state = cx.new(|_| AppState::new(vault_core::Uuid::new_v4(), Vec::new(), false));
        cx.update(|cx| {
            gpui_component::init(cx);
            cx.set_global(crate::RunningVault(state.clone()));
        });
        take_applied_policies();

        state.update(cx, |s, _| s.settings.show_in_dock = false);
        cx.update(crate::reopen_main_window);
        cx.run_until_parked();
        assert_eq!(take_applied_policies(), vec![ActivationPolicy::Accessory]);

        // Window already open: the early-return path re-asserts it too.
        cx.update(crate::reopen_main_window);
        cx.run_until_parked();
        assert_eq!(take_applied_policies(), vec![ActivationPolicy::Accessory]);

        state.update(cx, |s, _| s.settings.show_in_dock = true);
        cx.update(crate::reopen_main_window);
        cx.run_until_parked();
        assert!(take_applied_policies().is_empty());
    }

    /// Toggling the Dock icon activates only when a window exists: with none (background
    /// login start, 05 §2.5) the policy changes but Vault is not brought to the front.
    #[gpui::test]
    fn apply_dock_icon_activates_only_with_a_window(cx: &mut gpui::TestAppContext) {
        take_activations();
        take_applied_policies();
        cx.update(|cx| apply_dock_icon(true, cx));
        assert_eq!(take_applied_policies(), vec![ActivationPolicy::Regular]);
        assert_eq!(take_activations(), 0, "no window: no activation");

        cx.add_empty_window();
        cx.update(|cx| apply_dock_icon(false, cx));
        assert_eq!(take_applied_policies(), vec![ActivationPolicy::Accessory]);
        assert_eq!(take_activations(), 1, "window open: activates as before");
    }

    #[test]
    fn login_row_states() {
        assert_eq!(login_row(None), LoginRow::Hidden);
        assert_eq!(
            login_row(Some(LoginItemStatus::Unavailable)),
            LoginRow::Hidden
        );
        assert_eq!(
            login_row(Some(LoginItemStatus::NotFound)),
            LoginRow::Toggle(false)
        );
        assert_eq!(
            login_row(Some(LoginItemStatus::Enabled)),
            LoginRow::Toggle(true)
        );
        assert_eq!(
            login_row(Some(LoginItemStatus::RequiresApproval)),
            LoginRow::NeedsApproval
        );
        // The test binary is not an .app bundle: the row is hidden.
        assert!(!vault_macos::running_from_app_bundle());
    }
}
