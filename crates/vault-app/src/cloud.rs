//! iCloud hooks for vault-sync (specs/04-macos.md §4) and provider labels.
//!
//! vault-macos does not depend on vault-sync, so its `ICloudHooks` has inherent methods
//! only. [`ICloudAdapter`] supplies the `vault_sync::CloudHooks` impl by delegation.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use vault_sync::{CloudHooks, SyncLocation};

/// `vault_sync::CloudHooks` over `vault_macos::ICloudHooks`.
#[derive(Default)]
pub struct ICloudAdapter(vault_macos::ICloudHooks);

impl ICloudAdapter {
    pub fn new() -> Self {
        Self(vault_macos::ICloudHooks::new())
    }
}

/// One-to-one: both enums have the same two variants.
pub fn map_error(e: vault_macos::CloudError) -> vault_sync::CloudError {
    match e {
        vault_macos::CloudError::Timeout => vault_sync::CloudError::Timeout,
        vault_macos::CloudError::Other(msg) => vault_sync::CloudError::Other(msg),
    }
}

impl CloudHooks for ICloudAdapter {
    fn is_evicted(&self, path: &Path) -> bool {
        self.0.is_evicted(path)
    }

    fn ensure_downloaded(
        &self,
        path: &Path,
        timeout: Duration,
    ) -> Result<(), vault_sync::CloudError> {
        self.0.ensure_downloaded(path, timeout).map_err(map_error)
    }

    fn pin(&self, path: &Path) {
        self.0.pin(path);
    }
}

/// Hooks for one `SyncedVault`. Each vault owns its own, so its pin thread stops when the
/// vault is dropped.
pub fn hooks() -> Arc<dyn CloudHooks> {
    Arc::new(ICloudAdapter::new())
}

/// "iCloud Drive", "Dropbox", "OneDrive", "Google Drive", … for a vault file or folder; `None`
/// for a local folder. Classification is `vault_sync::classify_location` (path first, OS
/// ubiquity flag only as a fallback, since File Provider folders also report ubiquitous).
pub fn provider_label(path: &Path) -> Option<String> {
    let home = dirs::home_dir();
    match vault_sync::classify_location(path, home.as_deref(), || vault_macos::is_in_icloud(path)) {
        SyncLocation::Local => None,
        other => Some(other.label().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_one_to_one() {
        assert_eq!(
            map_error(vault_macos::CloudError::Timeout),
            vault_sync::CloudError::Timeout
        );
        assert_eq!(
            map_error(vault_macos::CloudError::Other("x".into())),
            vault_sync::CloudError::Other("x".into())
        );
    }

    #[test]
    fn adapter_passes_local_paths_through() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("t.vault");
        std::fs::write(&file, b"x").unwrap();
        let hooks = ICloudAdapter::new();
        assert!(!hooks.is_evicted(&file));
        assert_eq!(
            hooks.ensure_downloaded(&file, Duration::from_millis(10)),
            Ok(())
        );
        hooks.pin(&file);
    }

    #[test]
    fn provider_labels() {
        let icloud =
            Path::new("/Users/a/Library/Mobile Documents/com~apple~CloudDocs/Vaults/x.vault");
        assert_eq!(provider_label(icloud).as_deref(), Some("iCloud Drive"));
        let dropbox = Path::new("/Users/a/Library/CloudStorage/Dropbox/Vaults/x.vault");
        assert_eq!(provider_label(dropbox).as_deref(), Some("Dropbox"));
        let gdrive = Path::new("/Users/a/Library/CloudStorage/GoogleDrive-a@example.com/x.vault");
        assert_eq!(provider_label(gdrive).as_deref(), Some("Google Drive"));
        assert_eq!(provider_label(Path::new("/tmp/x.vault")), None);
    }
}
