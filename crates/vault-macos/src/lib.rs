//! macOS platform integration: device identity, idle and lock triggers,
//! pasteboard, iCloud eviction hooks, reduce-motion, Touch ID (Secure Enclave + Keychain).
//!
//! Packaging (spec 04 §7) is not implemented yet. Every public function here has a
//! `cfg(not(target_os = "macos"))` stub so dependents build on other hosts.

pub mod bookmark;
mod device;
mod error;
mod icloud;
mod idle;
mod pasteboard;
mod window;

pub use device::{BUNDLE_ID, DEVICE_ID_ENV, device_id, device_id_in, try_device_id};
pub use error::MacError;
pub use icloud::{
    CloudError, CloudProvider, ICloudHooks, PIN_INTERVAL, POLL_INTERVAL, cloud_provider,
    is_in_icloud,
};
pub use idle::{
    Subscription, boot_time, on_distributed_notification, on_screen_locked, on_user_switched,
    on_will_sleep, reduce_motion_enabled, seconds_since_user_input,
};
pub use pasteboard::{CONCEALED_TYPE, ChangeCount, Clipboard, PLAIN_TEXT_TYPE};
pub use window::exclude_app_windows_from_capture;
#[cfg(target_os = "macos")]
pub use window::exclude_window_from_capture;

mod biometric;
pub use biometric::Biometric;

mod login_item;
pub use login_item::{
    LoginItemStatus, login_item_status, open_login_items_settings, running_from_app_bundle,
    set_launch_at_login,
};

mod qr;
pub use qr::{
    MAX_IMAGE_FILE_BYTES, MAX_IMAGE_PIXELS, decode_qr_from_gray, scan_qr_from_image_file,
    scan_qr_from_screen, screen_capture_permitted,
};

mod appearance;
pub use appearance::{Rgba, on_system_colors_changed, system_accent_color};
