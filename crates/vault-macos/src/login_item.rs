//! Launch at login (spec 05 §2.5 General tab, phase 5) via `SMAppService`.
//!
//! Uses `SMAppService.mainAppService` (macOS 13+; our floor is 14). Registration
//! only works from a real `.app` bundle, so `set_launch_at_login` refuses with
//! `MacError::NotAvailable` before touching ServiceManagement when the process
//! runs from a bare binary (e.g. `cargo run`, `cargo test`).

use crate::MacError;

/// Registration state of the main app as a login item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItemStatus {
    /// Registered and allowed to launch at login.
    Enabled,
    /// Not registered.
    Disabled,
    /// Registered, but the user must allow it in System Settings > Login Items.
    RequiresApproval,
    /// ServiceManagement could not find the app's service.
    NotFound,
    /// Not supported on this platform, or an unknown status value.
    Unavailable,
}

/// Current login-item status of the main app.
pub fn login_item_status() -> LoginItemStatus {
    imp::status()
}

/// Register (`true`) or unregister (`false`) the main app as a login item.
///
/// Returns `MacError::NotAvailable` when not running from an `.app` bundle or
/// not on macOS, and `MacError::Other(localizedDescription)` when
/// ServiceManagement reports an error.
pub fn set_launch_at_login(enabled: bool) -> Result<(), MacError> {
    imp::set(enabled)
}

/// Open System Settings at the Login Items pane (for the `RequiresApproval`
/// case). No-op off macOS.
pub fn open_login_items_settings() {
    imp::open_settings()
}

/// True when the main bundle URL ends in `.app` (case-insensitive).
/// Always false off macOS.
pub fn running_from_app_bundle() -> bool {
    imp::running_from_app_bundle()
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2_foundation::NSBundle;
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    use super::LoginItemStatus;
    use crate::MacError;

    pub fn running_from_app_bundle() -> bool {
        NSBundle::mainBundle()
            .bundleURL()
            .pathExtension()
            .is_some_and(|ext| ext.to_string().eq_ignore_ascii_case("app"))
    }

    pub fn status() -> LoginItemStatus {
        // SAFETY: `mainAppService` is a class property with no preconditions
        // (macOS 13+, below our floor of 14); `status` is a plain getter on the
        // returned, retained object.
        let status = unsafe { SMAppService::mainAppService().status() };
        match status {
            SMAppServiceStatus::NotRegistered => LoginItemStatus::Disabled,
            SMAppServiceStatus::Enabled => LoginItemStatus::Enabled,
            SMAppServiceStatus::RequiresApproval => LoginItemStatus::RequiresApproval,
            SMAppServiceStatus::NotFound => LoginItemStatus::NotFound,
            _ => LoginItemStatus::Unavailable,
        }
    }

    pub fn set(enabled: bool) -> Result<(), MacError> {
        if !running_from_app_bundle() {
            return Err(MacError::NotAvailable);
        }
        // SAFETY: as in `status`; `mainAppService` has no preconditions.
        let service = unsafe { SMAppService::mainAppService() };
        let result = if enabled {
            // SAFETY: synchronous registration of the main app; the error
            // out-parameter is handled by the binding and surfaced as `Err`.
            unsafe { service.registerAndReturnError() }
        } else {
            // SAFETY: as above, for unregistration.
            unsafe { service.unregisterAndReturnError() }
        };
        result.map_err(|e| MacError::Other(e.localizedDescription().to_string()))
    }

    pub fn open_settings() {
        // SAFETY: class method with no arguments or preconditions; it only asks
        // System Settings to show the Login Items pane.
        unsafe { SMAppService::openSystemSettingsLoginItems() }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::LoginItemStatus;
    use crate::MacError;

    pub fn running_from_app_bundle() -> bool {
        false
    }

    pub fn status() -> LoginItemStatus {
        LoginItemStatus::Unavailable
    }

    pub fn set(_enabled: bool) -> Result<(), MacError> {
        Err(MacError::NotAvailable)
    }

    pub fn open_settings() {}
}
