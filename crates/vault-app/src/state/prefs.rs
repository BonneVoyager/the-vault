//! Settings ▸ General extras (specs/05-ui.md §2.5): launch at login and the first-run
//! tips card. Appearance and text size live in `Settings` and apply through `theme`.

use gpui::Context;
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
mod tests {
    use super::*;

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
