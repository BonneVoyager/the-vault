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

/// Sets `contentMinSize` to `width` x `height` points on the window that
/// owns `ns_view`, if that window is main-style: titled (`styleMask` contains
/// `titled`), not an `NSPanel` subclass and not a sheet. gpui only sets a
/// window's minimum size at creation, so `vault-app` calls this when one
/// window's minimum changes at runtime (for example, the collapsed sidebar);
/// other windows are never touched.
///
/// If the window is currently smaller than the new minimum, AppKit grows it
/// to fit on its next resize pass; this function does not resize it itself.
///
/// Returns true if the size was applied. Returns false, without touching the
/// pointer, when not called on the main thread; false when the view has no
/// window or the window fails the filter; always false off macOS.
///
/// # Safety
///
/// When called on the main thread, `ns_view` must point to a live AppKit
/// `NSView` (for example the `ns_view` of gpui's `AppKitWindowHandle`) and
/// must stay valid for the duration of the call. The pointer is not retained
/// past the call.
pub unsafe fn set_min_content_size_for_view(
    ns_view: std::ptr::NonNull<std::ffi::c_void>,
    width: f64,
    height: f64,
) -> bool {
    // SAFETY: forwarded caller contract (see `# Safety`).
    unsafe { imp::set_min_content_size_for_view(ns_view, width, height) }
}

/// Like [`set_min_content_size_for_view`], for `NSApp.keyWindow`. Returns
/// false when there is no key window, it fails the main-style filter, the
/// call is off the main thread, or off macOS.
pub fn set_key_window_min_content_size(width: f64, height: f64) -> bool {
    imp::set_key_window_min_content_size(width, height)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;
    use std::ptr::NonNull;

    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, NSObjectProtocol};
    use objc2::{MainThreadMarker, msg_send};
    use objc2_app_kit::{NSApplication, NSWindow, NSWindowStyleMask};
    use objc2_core_foundation::CGSize;

    /// Titled, not an `NSPanel` (or subclass), not a sheet.
    fn is_main_style(window: &NSWindow, panel: Option<&AnyClass>) -> bool {
        window.styleMask().contains(NSWindowStyleMask::Titled)
            && !panel.is_some_and(|cls| window.isKindOfClass(cls))
            && !window.isSheet()
    }

    /// Applies the filter and the size; true if applied.
    fn apply(window: &NSWindow, width: f64, height: f64) -> bool {
        if !is_main_style(window, AnyClass::get(c"NSPanel")) {
            return false;
        }
        window.setContentMinSize(CGSize::new(width, height));
        true
    }

    /// # Safety
    /// See `super::set_min_content_size_for_view`.
    pub unsafe fn set_min_content_size_for_view(
        ns_view: NonNull<c_void>,
        width: f64,
        height: f64,
    ) -> bool {
        if MainThreadMarker::new().is_none() {
            return false;
        }
        // SAFETY: the caller guarantees `ns_view` points to a live NSView for
        // the duration of this call, and NSView is an Objective-C object.
        let view: &AnyObject = unsafe { ns_view.cast::<AnyObject>().as_ref() };
        // SAFETY: `-[NSView window]` takes no arguments and returns a
        // nullable NSWindow (autoreleased, retained here); we are on the main
        // thread as NSView requires.
        let window: Option<Retained<NSWindow>> = unsafe { msg_send![view, window] };
        window.is_some_and(|w| apply(&w, width, height))
    }

    pub fn set_key_window_min_content_size(width: f64, height: f64) -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        NSApplication::sharedApplication(mtm)
            .keyWindow()
            .is_some_and(|w| apply(&w, width, height))
    }

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

    /// # Safety
    /// Never dereferences the pointer.
    pub unsafe fn set_min_content_size_for_view(
        _ns_view: std::ptr::NonNull<std::ffi::c_void>,
        _width: f64,
        _height: f64,
    ) -> bool {
        false
    }

    pub fn set_key_window_min_content_size(_width: f64, _height: f64) -> bool {
        false
    }
}
