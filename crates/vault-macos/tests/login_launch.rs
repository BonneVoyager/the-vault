//! Login-item launch detection (spec 04 §5d). `harness = false` so the check
//! runs on the process main thread: a test binary has no current Apple
//! Event, so the answer is false there too.

fn main() {
    #[cfg(target_os = "macos")]
    assert!(
        objc2::MainThreadMarker::new().is_some(),
        "harness = false runs on the main thread"
    );
    assert!(
        !vault_macos::launched_as_login_item(),
        "no Apple Event in a test binary"
    );

    let off = std::thread::spawn(vault_macos::launched_as_login_item)
        .join()
        .unwrap();
    assert!(!off, "off the main thread must be false");
    println!("login_launch: ok");
}
