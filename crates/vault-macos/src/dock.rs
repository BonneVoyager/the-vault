//! Dock icon visibility (spec 04 §5b) via `NSApp.activationPolicy`.
//!
//! `.regular` shows the Dock icon and the menu bar; `.accessory` hides both.
//! These functions never activate the app: after switching back to `.regular`
//! the caller re-activates it so AppKit draws the menu bar again.
//!
//! Main thread only. Off the main thread both functions return `false`
//! without touching AppKit.

/// Sets `NSApp.activationPolicy` to `.regular` (`visible == true`) or
/// `.accessory` (`visible == false`) and returns AppKit's `BOOL` result.
///
/// Returns `false` without changing anything when not called on the main
/// thread, and always `false` off macOS. Does not activate the app.
pub fn set_dock_icon_visible(visible: bool) -> bool {
    imp::set_dock_icon_visible(visible)
}

/// True when `NSApp.activationPolicy` is `.regular` (Dock icon shown).
///
/// Returns `false` when not called on the main thread, and always `false`
/// off macOS.
pub fn dock_icon_visible() -> bool {
    imp::dock_icon_visible()
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

    pub fn set_dock_icon_visible(visible: bool) -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        let policy = if visible {
            NSApplicationActivationPolicy::Regular
        } else {
            NSApplicationActivationPolicy::Accessory
        };
        NSApplication::sharedApplication(mtm).setActivationPolicy(policy)
    }

    pub fn dock_icon_visible() -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        NSApplication::sharedApplication(mtm).activationPolicy()
            == NSApplicationActivationPolicy::Regular
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn set_dock_icon_visible(_visible: bool) -> bool {
        false
    }

    pub fn dock_icon_visible() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // libtest runs tests on worker threads, so these exercise the
    // off-main-thread guard on macOS and the stub elsewhere: both report
    // `false` and nothing touches AppKit.

    #[test]
    fn dock_icon_visible_off_main_thread_is_false() {
        assert!(!dock_icon_visible());
    }

    #[test]
    fn set_dock_icon_visible_off_main_thread_is_refused() {
        assert!(!set_dock_icon_visible(true));
        assert!(!set_dock_icon_visible(false));
        assert!(!dock_icon_visible());
    }

    #[test]
    fn api_shape() {
        let _: fn(bool) -> bool = set_dock_icon_visible;
        let _: fn() -> bool = dock_icon_visible;
    }
}
