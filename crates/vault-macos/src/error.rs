//! Error type for platform calls (spec 04 §2).

/// Errors from macOS platform APIs.
#[derive(Debug, thiserror::Error)]
pub enum MacError {
    #[error("not available on this device")]
    NotAvailable,
    #[error("user cancelled")]
    UserCancelled,
    #[error("biometry set changed")]
    BiometryChanged,
    #[error("keychain error {0}")]
    Keychain(i32),
    #[error("{0}")]
    Other(String),
}
