use vault_macos::{on_screen_locked, on_user_switched, on_will_sleep, seconds_since_user_input};

#[test]
fn seconds_since_user_input_is_finite_and_non_negative() {
    let s = seconds_since_user_input();
    assert!(s.is_finite(), "{s}");
    assert!(s >= 0.0, "{s}");
}

#[cfg(target_os = "macos")]
#[test]
fn boot_time_is_plausible() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use vault_macos::boot_time;

    let t = boot_time();
    // 2020-01-01T00:00:00Z
    assert!(t > UNIX_EPOCH + Duration::from_secs(1_577_836_800), "{t:?}");
    assert!(t < SystemTime::now(), "{t:?}");
}

// Neither notification can be triggered from a test; this checks that
// registering and unregistering observers works headless without panicking.
#[test]
fn subscriptions_construct_and_drop() {
    let lock = on_screen_locked(|| {});
    let sleep = on_will_sleep(|| {});
    let switched = on_user_switched(|| {});
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&lock);
    assert_send(&switched);
    drop(lock);
    drop(sleep);
    drop(switched);
}

/// NSWorkspace's notification center is in-process and posts synchronously,
/// so posting the session-resign notification ourselves exercises the real
/// observer path without a run loop. A real user switch is not simulated.
#[cfg(target_os = "macos")]
#[test]
fn user_switched_delivers_and_stops_after_drop() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use objc2_app_kit::{NSWorkspace, NSWorkspaceSessionDidResignActiveNotification};

    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let sub = on_user_switched(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });

    let center = NSWorkspace::sharedWorkspace().notificationCenter();
    // SAFETY: AppKit initialises this extern constant at load time.
    let name = unsafe { NSWorkspaceSessionDidResignActiveNotification };
    // SAFETY: valid notification name, nil object.
    let post = || unsafe { center.postNotificationName_object(name, None) };

    post();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    drop(sub);
    post();
    assert_eq!(hits.load(Ordering::SeqCst), 1, "callback ran after drop");
}

#[test]
fn reduce_motion_does_not_panic() {
    let _ = vault_macos::reduce_motion_enabled();
}
