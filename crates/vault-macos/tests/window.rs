//! `sharingType` read-back for the best-effort capture exclusion
//! (spec 04, research §2c). `harness = false` because AppKit only allows
//! NSWindow on the process main thread. This checks the property AppKit
//! stores; whether capture is actually blocked is not testable here, and
//! Apple no longer guarantees it.

#[cfg(not(target_os = "macos"))]
fn main() {
    assert_eq!(vault_macos::exclude_app_windows_from_capture(), 0);
}

#[cfg(target_os = "macos")]
fn main() {
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{
        NSApplication, NSBackingStoreType, NSWindow, NSWindowSharingType, NSWindowStyleMask,
    };
    use objc2_foundation::{NSPoint, NSRect, NSSize};
    use vault_macos::{exclude_app_windows_from_capture, exclude_window_from_capture};

    let mtm = MainThreadMarker::new().expect("harness = false runs on the main thread");
    let _app = NSApplication::sharedApplication(mtm);
    let new_window = || {
        // SAFETY: designated initializer with a valid rect, a defined style
        // mask and backing type; deferred so no window server surface is
        // created. The window is never shown.
        let w = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(100.0, 100.0)),
                NSWindowStyleMask::Titled,
                NSBackingStoreType::Buffered,
                true,
            )
        };
        // SAFETY: we hold a Retained, so AppKit must not also release the
        // window on close.
        unsafe { w.setReleasedWhenClosed(false) };
        w
    };

    let a = new_window();
    assert_eq!(a.sharingType(), NSWindowSharingType::ReadOnly, "default");
    exclude_window_from_capture(&a);
    assert_eq!(a.sharingType(), NSWindowSharingType::None);

    let b = new_window();
    let n = exclude_app_windows_from_capture();
    assert!(
        n >= 2,
        "NSApp.windows should list both test windows, got {n}"
    );
    assert_eq!(b.sharingType(), NSWindowSharingType::None);

    // Off the main thread the app-wide variant is a no-op.
    let off = std::thread::spawn(exclude_app_windows_from_capture)
        .join()
        .unwrap();
    assert_eq!(off, 0);

    println!("window: ok");
}
