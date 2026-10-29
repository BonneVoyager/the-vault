//! Best-effort exclusion of our windows from screen capture
//! (docs/research/2026-10-29-hardware-key-and-unlocked-state.md §2c).
//!
//! This sets `NSWindow.sharingType = NSWindowSharingNone`. Apple's current
//! documentation for `NSWindow.SharingType.none` says:
//!
//! > A legacy constant that macOS no longer uses. `NSWindowSharingNone` can
//! > cause content to not be available in certain sharing situations. Don't
//! > use this value to hide or omit content from being captured. Instead, use
//! > FairPlay Streaming (FPS).
//!
//! We set it as best effort only. It must not be relied on, or described to
//! users, as protection against screenshots or screen recording.

/// Sets `sharingType = NSWindowSharingNone` on `window`. Best effort only:
/// macOS no longer guarantees that this hides the window from capture (see
/// the module docs for Apple's note).
#[cfg(target_os = "macos")]
pub fn exclude_window_from_capture(window: &objc2_app_kit::NSWindow) {
    window.setSharingType(objc2_app_kit::NSWindowSharingType::None);
}

/// Applies [`exclude_window_from_capture`]'s setting to every window the
/// application currently has (`NSApp.windows`), for callers such as the gpui
/// app that cannot name an `NSWindow`. Call it again after opening a window.
///
/// Best effort only; see the module docs. Returns how many windows were
/// updated: 0 when not called on the main thread, and always 0 off macOS.
pub fn exclude_app_windows_from_capture() -> usize {
    imp::exclude_app_windows_from_capture()
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;

    pub fn exclude_app_windows_from_capture() -> usize {
        let Some(mtm) = MainThreadMarker::new() else {
            return 0;
        };
        let windows = NSApplication::sharedApplication(mtm).windows();
        let n = windows.count();
        for i in 0..n {
            super::exclude_window_from_capture(&windows.objectAtIndex(i));
        }
        n
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn exclude_app_windows_from_capture() -> usize {
        0
    }
}
