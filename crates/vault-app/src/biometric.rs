//! Touch ID seam (specs/04-macos.md §2). `vault_macos::Biometric` needs a signed build
//! and a finger, so `AppState` talks to it through [`Biometrics`]; tests use the fake.

use std::sync::Arc;

use vault_core::{SecretVec, Uuid};
use vault_macos::{Biometric, MacError};

/// The `vault_macos::Biometric` API as a trait. Calls may block (Keychain, Secure Enclave,
/// the Touch ID sheet); `AppState` runs all but `available` and `is_enrolled` on the
/// background executor.
pub trait Biometrics: Send + Sync {
    fn available(&self) -> bool;
    fn enroll(&self, vault_id: Uuid, kek: &SecretVec<u8>, slot_id: Uuid) -> Result<(), MacError>;
    /// `(slot_id, kek)` after a successful Touch ID prompt showing `reason`.
    fn unlock(&self, vault_id: Uuid, reason: &str) -> Result<(Uuid, SecretVec<u8>), MacError>;
    fn is_enrolled(&self, vault_id: Uuid) -> bool;
    fn unenroll(&self, vault_id: Uuid) -> Result<(), MacError>;
}

/// The real Secure Enclave + Keychain implementation. Unused by tests (they use the fake).
#[cfg_attr(test, allow(dead_code))]
pub struct SystemBiometrics;

impl Biometrics for SystemBiometrics {
    fn available(&self) -> bool {
        Biometric::available()
    }

    fn enroll(&self, vault_id: Uuid, kek: &SecretVec<u8>, slot_id: Uuid) -> Result<(), MacError> {
        Biometric::enroll(vault_id, kek, slot_id)
    }

    fn unlock(&self, vault_id: Uuid, reason: &str) -> Result<(Uuid, SecretVec<u8>), MacError> {
        Biometric::unlock(vault_id, reason)
    }

    fn is_enrolled(&self, vault_id: Uuid) -> bool {
        Biometric::is_enrolled(vault_id)
    }

    fn unenroll(&self, vault_id: Uuid) -> Result<(), MacError> {
        Biometric::unenroll(vault_id)
    }
}

#[cfg_attr(test, allow(dead_code))]
pub fn system() -> Arc<dyn Biometrics> {
    Arc::new(SystemBiometrics)
}

#[cfg(test)]
pub mod fake {
    //! Records calls; `unlock` returns the enrolled KEK unless an error is queued.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use vault_core::ExposeSecret as _;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Call {
        Enroll(Uuid, Uuid),
        Unlock(Uuid, String),
        Unenroll(Uuid),
    }

    #[derive(Default)]
    pub struct Inner {
        pub available: bool,
        /// vault_id -> (slot_id, kek bytes).
        pub enrolled: HashMap<Uuid, (Uuid, Vec<u8>)>,
        pub calls: Vec<Call>,
        /// Returned by the next `unlock` instead of the stored KEK.
        pub next_unlock_error: Option<MacError>,
        /// Returned by the next `enroll`.
        pub next_enroll_error: Option<MacError>,
    }

    pub struct FakeBiometrics(pub Mutex<Inner>);

    impl FakeBiometrics {
        pub fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Inner {
                available: true,
                ..Inner::default()
            })))
        }

        pub fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
            f(&mut self.0.lock().unwrap())
        }

        pub fn calls(&self) -> Vec<Call> {
            self.with(|i| i.calls.clone())
        }
    }

    impl Biometrics for FakeBiometrics {
        fn available(&self) -> bool {
            self.with(|i| i.available)
        }

        fn enroll(
            &self,
            vault_id: Uuid,
            kek: &SecretVec<u8>,
            slot_id: Uuid,
        ) -> Result<(), MacError> {
            self.with(|i| {
                i.calls.push(Call::Enroll(vault_id, slot_id));
                if let Some(e) = i.next_enroll_error.take() {
                    return Err(e);
                }
                i.enrolled
                    .insert(vault_id, (slot_id, kek.expose_secret().clone()));
                Ok(())
            })
        }

        fn unlock(&self, vault_id: Uuid, reason: &str) -> Result<(Uuid, SecretVec<u8>), MacError> {
            self.with(|i| {
                i.calls.push(Call::Unlock(vault_id, reason.to_owned()));
                if let Some(e) = i.next_unlock_error.take() {
                    return Err(e);
                }
                i.enrolled
                    .get(&vault_id)
                    .map(|(slot, kek)| (*slot, SecretVec::new(kek.clone())))
                    .ok_or(MacError::Keychain(-25300))
            })
        }

        fn is_enrolled(&self, vault_id: Uuid) -> bool {
            self.with(|i| i.enrolled.contains_key(&vault_id))
        }

        fn unenroll(&self, vault_id: Uuid) -> Result<(), MacError> {
            self.with(|i| {
                i.calls.push(Call::Unenroll(vault_id));
                i.enrolled.remove(&vault_id);
                Ok(())
            })
        }
    }
}
