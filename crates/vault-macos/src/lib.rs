//! macOS platform integration: device identity, idle and lock triggers,
//! pasteboard, iCloud eviction hooks, reduce-motion, Touch ID (Secure Enclave + Keychain).
//!
//! Packaging (spec 04 §7) is not implemented yet. Every public function here has a
//! `cfg(not(target_os = "macos"))` stub so dependents build on other hosts.

pub mod bookmark;
mod device;
mod error;
mod host;
mod icloud;
mod idle;
mod pasteboard;
mod window;

pub use device::{BUNDLE_ID, DEVICE_ID_ENV, device_id, device_id_in, try_device_id};
pub use error::MacError;
pub use host::{model_identifier, os_version};
pub use icloud::{CloudError, ICloudHooks, PIN_INTERVAL, POLL_INTERVAL, is_in_icloud};
pub use idle::{
    Subscription, boot_time, on_distributed_notification, on_screen_locked, on_user_switched,
    on_will_sleep, reduce_motion_enabled, seconds_since_user_input,
};
pub use pasteboard::{CONCEALED_TYPE, ChangeCount, Clipboard, PLAIN_TEXT_TYPE};
#[cfg(target_os = "macos")]
pub use window::exclude_window_from_capture;
pub use window::{
    exclude_app_windows_from_capture, set_key_window_min_content_size,
    set_min_content_size_for_view,
};

mod biometric;
pub use biometric::Biometric;

mod login_item;
pub use login_item::{
    LoginItemStatus, login_item_status, open_login_items_settings, running_from_app_bundle,
    set_launch_at_login,
};

mod login_launch;
pub use login_launch::launched_as_login_item;

mod qr;
#[cfg(feature = "test-support")]
pub use qr::test_image_decoder_calls;
pub use qr::{
    MAX_IMAGE_FILE_BYTES, MAX_IMAGE_PIXELS, decode_qr_from_gray, scan_qr_from_image_file,
};

mod appearance;
pub use appearance::{Rgba, on_system_colors_changed, system_accent_color};

mod panel;
pub use panel::{cancel_open_panel, choose_file_async, normalize_extensions};

mod dock;
pub use dock::{dock_icon_visible, set_dock_icon_visible};

mod status_item;
pub use status_item::{StatusItem, StatusItemCallbacks, test_fallback_glyph_size};
