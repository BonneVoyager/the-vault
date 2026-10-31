//! `sharingType` read-back for the best-effort capture exclusion
//! (spec 04, research §2c). `harness = false` because AppKit only allows
//! NSWindow on the process main thread. This checks the property AppKit
//! stores; whether capture is actually blocked is not testable here, and
//! Apple no longer guarantees it.

#[cfg(not(target_os = "macos"))]
fn main() {
    assert_eq!(vault_macos::exclude_app_windows_from_capture(), 0);
    assert!(!vault_macos::set_key_window_min_content_size(600.0, 400.0));
    let p = std::ptr::NonNull::<std::ffi::c_void>::dangling();
    // SAFETY: the stub never dereferences the pointer.
    assert!(!unsafe { vault_macos::set_min_content_size_for_view(p, 600.0, 400.0) });
}

#[cfg(target_os = "macos")]
fn main() {
    use objc2::rc::Allocated;
    use objc2::runtime::{AnyClass, AnyObject};
    use objc2::{MainThreadMarker, MainThreadOnly, msg_send};
    use objc2_app_kit::{
        NSApplication, NSBackingStoreType, NSWindow, NSWindowSharingType, NSWindowStyleMask,
    };
    use objc2_foundation::{NSPoint, NSRect, NSSize};
    use std::ffi::c_void;
    use std::ptr::NonNull;
    use vault_macos::{
        exclude_app_windows_from_capture, exclude_window_from_capture,
        set_key_window_min_content_size, set_min_content_size_for_view,
    };

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

    // Min content size: only the targeted titled window changes, never a panel.
    let panel_cls = AnyClass::get(c"NSPanel").expect("AppKit is linked");
    // SAFETY: `+[NSPanel alloc]` returns an uninitialised NSPanel, which is
    // an NSWindow subclass, so typing it as Allocated<NSWindow> is sound.
    let panel_alloc: Allocated<NSWindow> = unsafe { msg_send![panel_cls, alloc] };
    // SAFETY: as for `new_window`; NSPanel inherits this designated
    // initializer. Deferred and never shown.
    let panel = unsafe {
        NSWindow::initWithContentRect_styleMask_backing_defer(
            panel_alloc,
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(100.0, 100.0)),
            NSWindowStyleMask::Titled | NSWindowStyleMask::UtilityWindow,
            NSBackingStoreType::Buffered,
            true,
        )
    };
    // SAFETY: we hold a Retained, so AppKit must not also release it on close.
    unsafe { panel.setReleasedWhenClosed(false) };
    let panel_before = panel.contentMinSize();

    let content_view = |w: &NSWindow| -> NonNull<c_void> {
        // SAFETY: `-[NSWindow contentView]` takes no arguments; a titled
        // window created by the designated initializer always has one.
        let v: *mut AnyObject = unsafe { msg_send![w, contentView] };
        NonNull::new(v.cast()).expect("window has a content view")
    };
    let a_view = content_view(&a);
    let b_before = b.contentMinSize();

    // SAFETY: `a_view` is `a`'s content view; `a` is alive and we are on the
    // main thread.
    assert!(unsafe { set_min_content_size_for_view(a_view, 820.0, 500.0) });
    assert_eq!(a.contentMinSize(), NSSize::new(820.0, 500.0));
    // SAFETY: as above.
    assert!(unsafe { set_min_content_size_for_view(a_view, 600.0, 400.0) });
    assert_eq!(a.contentMinSize(), NSSize::new(600.0, 400.0));
    assert_eq!(b.contentMinSize(), b_before, "other windows untouched");

    let panel_view = content_view(&panel);
    // SAFETY: `panel_view` is the live panel's content view; main thread.
    assert!(!unsafe { set_min_content_size_for_view(panel_view, 820.0, 500.0) });
    assert_eq!(panel.contentMinSize(), panel_before, "panel untouched");

    // Off the main thread it returns false without touching the pointer.
    let addr = a_view.as_ptr() as usize;
    let off = std::thread::spawn(move || {
        let p = NonNull::new(addr as *mut c_void).unwrap();
        // SAFETY: off the main thread the function returns before using `p`.
        unsafe { set_min_content_size_for_view(p, 1.0, 1.0) }
    })
    .join()
    .unwrap();
    assert!(!off);
    assert_eq!(a.contentMinSize(), NSSize::new(600.0, 400.0));

    // No window was ever shown, so there is no key window.
    assert!(!set_key_window_min_content_size(820.0, 500.0));
    assert_eq!(a.contentMinSize(), NSSize::new(600.0, 400.0));

    println!("window: ok");
}
