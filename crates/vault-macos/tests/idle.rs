use vault_macos::{on_screen_locked, on_will_sleep, seconds_since_user_input};

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
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&lock);
    drop(lock);
    drop(sleep);
}

#[test]
fn reduce_motion_does_not_panic() {
    let _ = vault_macos::reduce_motion_enabled();
}
