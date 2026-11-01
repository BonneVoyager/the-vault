//! Cloud-provider hooks (03 §7). `vault-macos` supplies the iCloud implementation.
//! Also the pure path classifier behind the "which provider syncs this vault" label
//! ([`classify_location`]). It reads path components only (no I/O, no canonicalisation) and
//! compares them ASCII case-insensitively, as the default APFS volume does, and in NFC (the
//! home directory's user name may arrive decomposed). A
//! `Library/Mobile Documents` pair anywhere in the path, including on another volume
//! (`/Volumes/x/Library/Mobile Documents/…`), reads as iCloud Drive: that folder exists only
//! for iCloud, so the simple rule is kept.

use std::path::{Component, Path};
use std::time::Duration;

use crate::package;

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

/// Who syncs a vault's folder, for display (03 §1 "Provider label").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncLocation {
    /// Under `~/Library/Mobile Documents/` (any container), or reported ubiquitous by the OS.
    ICloudDrive,
    /// A File Provider folder `~/Library/CloudStorage/<Prefix>-…`, or the legacy `~/Dropbox`.
    /// Holds the display name: "Dropbox", "OneDrive", "Google Drive", "Box", or the raw prefix.
    Provider(String),
    /// Anything else.
    Local,
}

impl SyncLocation {
    /// "iCloud Drive", the provider name, or "Local folder".
    pub fn label(&self) -> &str {
        match self {
            Self::ICloudDrive => "iCloud Drive",
            Self::Provider(name) => name,
            Self::Local => "Local folder",
        }
    }
}

/// Classify `path` (the vault package or the folder it lives in) by path alone, falling back to
/// `is_ubiquitous` (the OS's `NSURLIsUbiquitousItemKey`) only when the path decides nothing.
///
/// Rules, first match wins, judged on the first `Library/Mobile Documents` or
/// `Library/CloudStorage` pair in the path:
/// - `…/Library/Mobile Documents/…` -> iCloud Drive.
/// - `…/Library/CloudStorage/<folder>/…` -> the provider named by `<folder>`'s prefix before the
///   first `-` (`Dropbox`, `OneDrive`, `GoogleDrive` -> "Google Drive", `Box`, else the raw
///   prefix). Only that segment counts: a deeper folder called "Dropbox" changes nothing.
/// - `<home>/Dropbox` or `<home>/Dropbox (<team>)` (legacy, pre-File-Provider) -> Dropbox.
/// - otherwise iCloud Drive if `is_ubiquitous()`, else Local.
///
/// The ubiquity check comes last on purpose: macOS reports File Provider items (Dropbox,
/// OneDrive, Google Drive under `CloudStorage`) as ubiquitous too.
pub fn classify_location(
    path: &Path,
    home: Option<&Path>,
    is_ubiquitous: impl FnOnce() -> bool,
) -> SyncLocation {
    let names = normal_names(path);
    for (i, pair) in names.windows(2).enumerate() {
        if !eq(pair[0], "Library") {
            continue;
        }
        if eq(pair[1], "Mobile Documents") {
            return SyncLocation::ICloudDrive;
        }
        if eq(pair[1], "CloudStorage")
            && let Some(folder) = names.get(i + 2)
        {
            return SyncLocation::Provider(provider_name(folder));
        }
    }
    if let Some(first) = first_under_home(&names, home)
        && (eq(first, "Dropbox") || starts_with_ci(first, "Dropbox ("))
    {
        return SyncLocation::Provider("Dropbox".to_owned());
    }
    if is_ubiquitous() {
        SyncLocation::ICloudDrive
    } else {
        SyncLocation::Local
    }
}

/// The path's normal components as UTF-8 (root, `.`, `..` and non-UTF-8 parts dropped).
/// Trailing slashes and repeated separators never produce components.
fn normal_names(path: &Path) -> Vec<&str> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect()
}

fn eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len()).is_some_and(|p| eq(p, prefix))
}

/// The first component below the home directory, if `names` lies under it.
///
/// A leading `~` stands for the home directory (with or without `home`). Otherwise the home
/// is recognised by its last two components (`Users/<name>`), matched case-insensitively at
/// their first occurrence in the path, so the symlinked and canonical forms
/// (`/Users/a`, `/System/Volumes/Data/Users/a`) both match whichever form `home` is given
/// in. A home with a single component (`/root`) is matched by that component.
fn first_under_home<'a>(names: &[&'a str], home: Option<&Path>) -> Option<&'a str> {
    if names.first() == Some(&"~") {
        return names.get(1).copied();
    }
    let home = normal_names(home?);
    let tail = &home[home.len().saturating_sub(2)..];
    if tail.is_empty() || names.len() <= tail.len() {
        return None;
    }
    names
        .windows(tail.len())
        .position(|w| {
            w.iter()
                .zip(tail)
                .all(|(a, b)| eq(&package::nfc(a), &package::nfc(b)))
        })
        .and_then(|i| names.get(i + tail.len()).copied())
}

/// Display name for a `~/Library/CloudStorage/<folder>` entry, e.g. `OneDrive-Personal`:
/// the prefix before the first `-`; known providers get their canonical spelling.
fn provider_name(folder: &str) -> String {
    let prefix = match folder.split_once('-') {
        Some((p, _)) if !p.is_empty() => p,
        _ => folder,
    };
    let known = [
        ("Dropbox", "Dropbox"),
        ("OneDrive", "OneDrive"),
        ("GoogleDrive", "Google Drive"),
        ("Box", "Box"),
    ];
    known
        .iter()
        .find(|(k, _)| eq(k, prefix))
        .map_or_else(|| prefix.to_owned(), |(_, label)| (*label).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/Users/a";

    fn classify(path: &str, ubiquitous: bool) -> String {
        classify_location(Path::new(path), Some(Path::new(HOME)), || ubiquitous)
            .label()
            .to_owned()
    }

    #[test]
    fn icloud_drive_by_path_or_ubiquity() {
        let docs = "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/Vaults/x.vault";
        assert_eq!(classify(docs, false), "iCloud Drive");
        let app = "/Users/a/Library/Mobile Documents/iCloud~com~example~app/Documents/x.vault";
        assert_eq!(classify(app, false), "iCloud Drive");
        // Not under a known folder, but the OS says ubiquitous (e.g. Desktop & Documents sync).
        assert_eq!(classify("/Users/a/Documents/x.vault", true), "iCloud Drive");
    }

    #[test]
    fn cloud_storage_providers_by_folder_prefix() {
        let cases = [
            ("Dropbox", "Dropbox"),
            ("Dropbox-Personal", "Dropbox"),
            ("OneDrive-Personal", "OneDrive"),
            ("OneDrive-SharedLibraries-Contoso", "OneDrive"),
            ("GoogleDrive-a@example.com", "Google Drive"),
            ("Box-Box", "Box"),
            ("pCloud-a@example.com", "pCloud"),
            ("SomeSync", "SomeSync"),
        ];
        for (folder, label) in cases {
            let path = format!("/Users/a/Library/CloudStorage/{folder}/Vaults/x.vault");
            // Ubiquity is true for File Provider items; it must not turn them into iCloud.
            assert_eq!(classify(&path, true), label, "{folder}");
            assert_eq!(classify(&path, false), label, "{folder}");
        }
    }

    #[test]
    fn deeper_dropbox_folder_does_not_decide() {
        let gdrive =
            "/Users/a/Library/CloudStorage/GoogleDrive-a@example.com/My Drive/Dropbox/x.vault";
        assert_eq!(classify(gdrive, true), "Google Drive");
        let onedrive = "/Users/a/Library/CloudStorage/OneDrive-Personal/Dropbox/x.vault";
        assert_eq!(classify(onedrive, false), "OneDrive");
        assert_eq!(
            classify("/Users/a/Documents/Dropbox/x.vault", false),
            "Local folder"
        );
        assert_eq!(
            classify("/Volumes/nas/Dropbox/x.vault", false),
            "Local folder"
        );
    }

    #[test]
    fn legacy_dropbox_in_home() {
        assert_eq!(classify("/Users/a/Dropbox/x.vault", false), "Dropbox");
        assert_eq!(classify("/Users/a/Dropbox/Vaults/x.vault", true), "Dropbox");
        assert_eq!(
            classify("/Users/a/Dropbox (Acme)/x.vault", false),
            "Dropbox"
        );
        assert_eq!(
            classify("/Users/a/Dropboxes/x.vault", false),
            "Local folder"
        );
        // Without a known home the legacy rule cannot apply.
        let no_home = classify_location(Path::new("/Users/a/Dropbox/x.vault"), None, || false);
        assert_eq!(no_home, SyncLocation::Local);
    }

    #[test]
    fn tilde_paths() {
        assert_eq!(classify("~/Dropbox/x.vault", false), "Dropbox");
        assert_eq!(classify("~/Documents/x.vault", false), "Local folder");
        assert_eq!(
            classify("~/Library/CloudStorage/OneDrive-Personal/x.vault", true),
            "OneDrive"
        );
        assert_eq!(
            classify("~/Library/Mobile Documents/com~apple~CloudDocs/x", false),
            "iCloud Drive"
        );
        // A leading `~` is the home even when the caller has none.
        let got = classify_location(Path::new("~/Dropbox/x.vault"), None, || false);
        assert_eq!(got.label(), "Dropbox");
    }

    #[test]
    fn symlinked_or_canonical_home() {
        let canonical = "/System/Volumes/Data/Users/a/Dropbox/x.vault";
        assert_eq!(classify(canonical, false), "Dropbox");
        // Home given in canonical form, path in the usual one.
        let home = Path::new("/System/Volumes/Data/Users/a");
        let got = classify_location(Path::new("/Users/a/Dropbox/x.vault"), Some(home), || false);
        assert_eq!(got.label(), "Dropbox");
        // Home component case differs from the path.
        let got = classify_location(
            Path::new("/users/A/Dropbox/x.vault"),
            Some(Path::new("/Users/a")),
            || false,
        );
        assert_eq!(got.label(), "Dropbox");
        // Another user's Dropbox is not under this home.
        assert_eq!(classify("/Users/b/Dropbox/x.vault", false), "Local folder");
        // Single-component home.
        let got = classify_location(
            Path::new("/root/Dropbox/x"),
            Some(Path::new("/root")),
            || false,
        );
        assert_eq!(got.label(), "Dropbox");
        // A root home matches nothing.
        let got = classify_location(Path::new("/Dropbox/x"), Some(Path::new("/")), || false);
        assert_eq!(got.label(), "Local folder");
    }

    #[test]
    fn case_insensitive_components() {
        assert_eq!(classify("/Users/a/dropbox/x.vault", false), "Dropbox");
        assert_eq!(classify("/Users/a/DROPBOX/x.vault", false), "Dropbox");
        assert_eq!(
            classify("/Users/a/dropbox (Acme)/x.vault", false),
            "Dropbox"
        );
        assert_eq!(
            classify("/Users/a/library/cloudstorage/dropbox/x.vault", true),
            "Dropbox"
        );
        assert_eq!(
            classify(
                "/Users/a/Library/CloudStorage/googledrive-a@example.com/x",
                true
            ),
            "Google Drive"
        );
        assert_eq!(
            classify("/Users/a/LIBRARY/mobile documents/x", false),
            "iCloud Drive"
        );
    }

    #[test]
    fn trailing_slashes() {
        assert_eq!(classify("/Users/a/Dropbox/", false), "Dropbox");
        assert_eq!(
            classify("/Users/a/Dropbox//Vaults//x.vault/", false),
            "Dropbox"
        );
        assert_eq!(
            classify("/Users/a/Library/CloudStorage/Box-Box/", false),
            "Box"
        );
        let got = classify_location(
            Path::new("/Users/a/Dropbox/x.vault/"),
            Some(Path::new("/Users/a/")),
            || false,
        );
        assert_eq!(got.label(), "Dropbox");
    }

    #[test]
    fn mobile_documents_on_another_volume_is_icloud() {
        let path = "/Volumes/x/Library/Mobile Documents/com~apple~CloudDocs/x.vault";
        assert_eq!(classify(path, false), "iCloud Drive");
    }

    #[test]
    fn local_folders() {
        assert_eq!(classify("/tmp/x.vault", false), "Local folder");
        assert_eq!(
            classify("/Users/a/Documents/x.vault", false),
            "Local folder"
        );
        // "CloudStorage" itself, with no provider folder below it, decides nothing.
        assert_eq!(
            classify("/Users/a/Library/CloudStorage", false),
            "Local folder"
        );
    }

    #[test]
    fn home_prefix_matches_whole_components_only() {
        let alice = Path::new("/Users/alice");
        let alicia = Path::new("/Users/alicia");
        let under = |path: &str, home: &Path| {
            classify_location(Path::new(path), Some(home), || false)
                .label()
                .to_owned()
        };
        assert_eq!(under("/Users/alice/Dropbox/x.vault", alice), "Dropbox");
        assert_eq!(under("/Users/alicia/Dropbox/x.vault", alicia), "Dropbox");
        // A home is not a string prefix of another user's home, in either direction.
        assert_eq!(
            under("/Users/alicia/Dropbox/x.vault", alice),
            "Local folder"
        );
        assert_eq!(
            under("/Users/alice/Dropbox/x.vault", alicia),
            "Local folder"
        );
        assert_eq!(
            under("/Users/alice/Dropbox/x.vault", Path::new("/Users/ali")),
            "Local folder"
        );
        // Case variants of the home still match whole components only.
        assert_eq!(under("/USERS/ALICE/dropbox/x.vault", alice), "Dropbox");
        assert_eq!(
            under("/users/ALICIA/Dropbox/x.vault", alice),
            "Local folder"
        );
        assert_eq!(
            under("/Users/ALICE/Dropbox/x.vault", alicia),
            "Local folder"
        );
    }

    #[test]
    fn home_matches_across_normalisation_forms() {
        let got = classify_location(
            Path::new("/Users/Jose\u{301}/Dropbox/x.vault"),
            Some(Path::new("/Users/Jos\u{e9}")),
            || false,
        );
        assert_eq!(got.label(), "Dropbox");
        let got = classify_location(
            Path::new("/Users/Jose/Dropbox/x.vault"),
            Some(Path::new("/Users/Jos\u{e9}")),
            || false,
        );
        assert_eq!(got.label(), "Local folder");
    }

    #[test]
    fn cloud_storage_prefix_is_whole_component() {
        for (library, storage) in [
            ("Library", "CloudStorage"),
            ("library", "cloudstorage"),
            ("LIBRARY", "CLOUDSTORAGE"),
        ] {
            let ok = format!("/Users/a/{library}/{storage}/Dropbox/x.vault");
            assert_eq!(classify(&ok, false), "Dropbox", "{ok}");
            // Longer or shorter components that merely start or end with the names.
            for bad in [
                format!("/Users/a/{library}/{storage}X/Dropbox/x.vault"),
                format!("/Users/a/{library}/X{storage}/Dropbox/x.vault"),
                format!("/Users/a/{library}X/{storage}/Dropbox/x.vault"),
                format!("/Users/a/{library}/Cloud/Dropbox/x.vault"),
                format!("/Users/a/{library}{storage}/Dropbox/x.vault"),
                format!("/Users/a/{library} {storage}/Dropbox/x.vault"),
            ] {
                assert_eq!(classify(&bad, false), "Local folder", "{bad}");
            }
        }
        // The provider folder's prefix is its whole segment before the first `-`.
        for (folder, label) in [
            ("DropboxPlus", "DropboxPlus"),
            ("dropboxplus-x", "dropboxplus"),
            ("Boxed-x", "Boxed"),
            ("BOX-x", "Box"),
            ("box", "Box"),
            ("onedrive-Personal", "OneDrive"),
            ("ONEDRIVE", "OneDrive"),
            ("OneDriveX-Personal", "OneDriveX"),
        ] {
            let path = format!("/Users/a/Library/CloudStorage/{folder}/x.vault");
            assert_eq!(classify(&path, false), label, "{folder}");
        }
    }

    #[test]
    fn ubiquity_is_not_queried_when_the_path_decides() {
        let path = Path::new("/Users/a/Library/CloudStorage/Dropbox/x.vault");
        let got = classify_location(path, None, || panic!("queried"));
        assert_eq!(got, SyncLocation::Provider("Dropbox".into()));
    }
}
