//! Accent colour and system-colours notification (harness = false: the
//! accent colour is only read on the process main thread).

#[cfg(not(target_os = "macos"))]
fn main() {
    assert!(vault_macos::system_accent_color().is_none());
    drop(vault_macos::on_system_colors_changed(|| {}));
}

#[cfg(target_os = "macos")]
fn main() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use objc2_app_kit::NSSystemColorsDidChangeNotification;
    use objc2_foundation::NSNotificationCenter;
    use vault_macos::{on_system_colors_changed, system_accent_color};

    // Main thread: Some, components in range.
    let c = system_accent_color().expect("accent colour on the main thread");
    for v in [c.r, c.g, c.b, c.a] {
        assert!((0.0..=1.0).contains(&v), "{c:?}");
    }
    assert!(c.a > 0.0, "{c:?}");

    // Off the main thread: None.
    let off = std::thread::spawn(system_accent_color).join().unwrap();
    assert!(off.is_none(), "{off:?}");

    // Subscription constructs and drops.
    drop(on_system_colors_changed(|| {}));

    // The default center posts synchronously in-process: delivered once,
    // not after drop.
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let sub = on_system_colors_changed(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&sub);
    let center = NSNotificationCenter::defaultCenter();
    // SAFETY: AppKit initialises this extern constant at load time.
    let name = unsafe { NSSystemColorsDidChangeNotification };
    // SAFETY: valid notification name, nil object.
    let post = || unsafe { center.postNotificationName_object(name, None) };
    post();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    drop(sub);
    post();
    assert_eq!(hits.load(Ordering::SeqCst), 1, "callback ran after drop");

    println!("appearance: 4 checks passed");
}
