//! `Biometric` (spec 04 §2, §8).
//!
//! On an unsigned `cargo test` build the non-ignored tests pass vacuously: the data
//! protection keychain rejects the binary, so `is_enrolled` sees errSecItemNotFound
//! (-25300) or errSecMissingEntitlement (-34018) and `unenroll` gets -34018. They only
//! prove the calls return without panicking. (Ad-hoc signing with keychain-access-groups
//! gets the binary killed by AMFI, so it cannot be used to work around this.)
//!
//! The real acceptance test is the `#[ignore]`d `enroll_unlock_unenroll`. It needs Touch ID
//! hardware, a finger touch, and a Developer-ID-signed build carrying the
//! keychain-access-groups entitlement plus its provisioning profile. Run it on such a build
//! before packaging (§7) ships:
//!
//! ```text
//! cargo test -p vault-macos --test biometric -- --ignored --nocapture
//! ```
//!
//! (Sign the produced test binary under `target/debug/deps/biometric-*` with the app's
//! identity and entitlements, then run it with `--ignored`.)

use secrecy::{ExposeSecret, SecretVec};
use uuid::Uuid;
use vault_macos::{Biometric, MacError};

#[test]
fn available_does_not_panic() {
    let _ = Biometric::available();
}

#[test]
fn unknown_vault_is_not_enrolled() {
    let id = Uuid::new_v4();
    assert!(!Biometric::is_enrolled(id));
}

#[cfg(target_os = "macos")]
#[test]
fn unenroll_unknown_vault_is_ok() {
    match Biometric::unenroll(Uuid::new_v4()) {
        Ok(()) => {}
        // Unsigned `cargo test` binaries cannot reach the data protection keychain at all;
        // ad-hoc signing with keychain-access-groups is killed by AMFI. A signed build with
        // the entitlement returns Ok here.
        Err(MacError::Keychain(ERR_SEC_MISSING_ENTITLEMENT)) => {}
        Err(e) => panic!("unenroll of an unknown vault failed: {e:?}"),
    }
}

#[cfg(target_os = "macos")]
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

#[cfg(not(target_os = "macos"))]
#[test]
fn stubs_report_not_available() {
    let id = Uuid::new_v4();
    assert!(!Biometric::available());
    assert!(matches!(
        Biometric::unenroll(id),
        Err(MacError::NotAvailable)
    ));
    assert!(matches!(
        Biometric::unlock(id, "x"),
        Err(MacError::NotAvailable)
    ));
}

#[test]
fn enroll_rejects_short_kek() {
    let r = Biometric::enroll(Uuid::new_v4(), &SecretVec::new(vec![0; 16]), Uuid::new_v4());
    assert!(matches!(
        r,
        Err(MacError::Other(_)) | Err(MacError::NotAvailable)
    ));
}

#[test]
#[ignore = "needs Touch ID, a finger touch and a signed binary; run manually"]
fn enroll_unlock_unenroll() {
    let vault_id = Uuid::new_v4();
    let slot_id = Uuid::new_v4();
    // Test-only KEK: two v4 UUIDs (OS randomness) avoid a rand dev-dependency.
    let raw = [*Uuid::new_v4().as_bytes(), *Uuid::new_v4().as_bytes()].concat();
    let kek = SecretVec::new(raw);

    assert!(Biometric::available(), "Touch ID not available");
    Biometric::enroll(vault_id, &kek, slot_id).expect("enroll");
    assert!(Biometric::is_enrolled(vault_id));

    let result = Biometric::unlock(vault_id, "unlock the vault-macos test vault");
    let cleanup = Biometric::unenroll(vault_id);
    let (got_slot, got_kek) = result.expect("unlock");
    cleanup.expect("unenroll");

    assert_eq!(got_slot, slot_id);
    assert_eq!(got_kek.expose_secret(), kek.expose_secret());
    assert!(!Biometric::is_enrolled(vault_id));
}
