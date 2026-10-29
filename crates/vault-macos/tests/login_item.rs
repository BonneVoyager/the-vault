//! Launch-at-login (SMAppService) tests.

use vault_macos::{
    LoginItemStatus, MacError, login_item_status, running_from_app_bundle, set_launch_at_login,
};

#[test]
fn status_returns_without_panicking() {
    let _ = login_item_status();
}

#[test]
fn test_binary_is_not_an_app_bundle() {
    assert!(!running_from_app_bundle());
}

#[test]
fn register_from_bare_binary_is_refused_before_service_management() {
    let before = login_item_status();
    assert!(matches!(
        set_launch_at_login(true),
        Err(MacError::NotAvailable)
    ));
    assert!(matches!(
        set_launch_at_login(false),
        Err(MacError::NotAvailable)
    ));
    assert_eq!(login_item_status(), before);
}

/// Manual: only meaningful from a packaged, signed `.app` (e.g. a test bundle
/// wrapping this binary). Registers, checks the status, then unregisters.
/// Run with `cargo test -p vault-macos --test login_item -- --ignored` from
/// inside the bundle.
#[test]
#[ignore = "needs a packaged .app; registers a real login item"]
fn manual_register_and_unregister_from_app_bundle() {
    assert!(running_from_app_bundle(), "run from inside a packaged .app");
    set_launch_at_login(true).expect("register");
    let status = login_item_status();
    assert!(
        matches!(
            status,
            LoginItemStatus::Enabled | LoginItemStatus::RequiresApproval
        ),
        "unexpected status after register: {status:?}"
    );
    set_launch_at_login(false).expect("unregister");
    assert_eq!(login_item_status(), LoginItemStatus::Disabled);
}
