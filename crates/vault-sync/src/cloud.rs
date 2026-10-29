//! Cloud-provider hooks (03 §7). `vault-macos` supplies the iCloud implementation.

use std::path::Path;
use std::time::Duration;

/// Failure reported by [`CloudHooks::ensure_downloaded`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CloudError {
    /// The provider did not materialise the file within the timeout.
    #[error("timed out waiting for the cloud provider to download the file")]
    Timeout,
    /// Any other provider failure.
    #[error("cloud provider error: {0}")]
    Other(String),
}

/// Calls into the cloud provider that owns the vault's directory, if any.
pub trait CloudHooks: Send + Sync {
    /// Returns true if the file is a placeholder that must be downloaded first.
    fn is_evicted(&self, path: &Path) -> bool;
    /// Request download; blocks up to `timeout`.
    fn ensure_downloaded(&self, path: &Path, timeout: Duration) -> Result<(), CloudError>;
    /// Hint to the provider that this file should never be evicted (best effort).
    fn pin(&self, path: &Path);
}

/// Default hooks for plain local directories and tests: nothing is ever evicted.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopHooks;

impl CloudHooks for NoopHooks {
    fn is_evicted(&self, _path: &Path) -> bool {
        false
    }

    fn ensure_downloaded(&self, _path: &Path, _timeout: Duration) -> Result<(), CloudError> {
        Ok(())
    }

    fn pin(&self, _path: &Path) {}
}
