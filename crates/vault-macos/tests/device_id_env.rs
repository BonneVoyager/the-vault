//! Env-var behaviour of `try_device_id`. Separate test binary with a single
//! test so mutating the process environment cannot race other tests.

use uuid::Uuid;
use vault_macos::{DEVICE_ID_ENV, MacError, device_id, try_device_id};

#[test]
fn env_override_and_bad_value() {
    let id = Uuid::new_v4();
    // SAFETY: this is the only test in this binary, so no other thread reads
    // or writes the environment concurrently.
    unsafe { std::env::set_var(DEVICE_ID_ENV, id.to_string()) };
    assert_eq!(try_device_id().unwrap(), id);
    assert_eq!(device_id(), id);

    // SAFETY: as above.
    unsafe { std::env::set_var(DEVICE_ID_ENV, "not-a-uuid") };
    assert!(matches!(try_device_id(), Err(MacError::Other(_))));
    // Infallible wrapper falls back to a stable per-process id.
    let a = device_id();
    assert_eq!(a, device_id());
    assert_ne!(a, id);
}
