//! The filesystem watcher (03 §1, §3) and conflicted-package name patterns (03 §6).
//!
//! One recursive watch on the package's parent directory covers both the package (only
//! `vault.bin` matters; `attachments/` holds immutable blobs and `backups/` is ours, so both
//! are ignored) and sibling `*.vault` packages that a cloud provider created as conflicted
//! copies, including a `vault.bin` that arrives inside one after the directory itself. FSEvents
//! watches whole subtrees at the OS level anyway, so this costs one stream start, where a
//! second watch for the package would restart the stream. The debouncer runs without a file-id
//! cache: the recommended macOS cache walks every recursively watched tree up front (possibly
//! all of iCloud Drive), and path classification needs no file ids.
//!
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};
use notify::{EventKind, RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, Debouncer, NoCache, new_debouncer_opt};

use crate::atomic::parent_dir;
use crate::error::SyncError;
use crate::package::{self, VAULT_FILE_NAME};

/// Debounce window (03 §3).
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// What the watcher thread tells `SyncedVault::poll`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchSignal {
    /// Something happened to `<name>.vault/vault.bin` (or to the package directory itself).
    PrimaryChanged,
    /// A `*.vault` sibling package, or a `vault*.bin` file inside our package, appeared or
    /// changed; it may be a conflicted copy (03 §6).
    CandidateConflict(PathBuf),
    /// The watcher itself reported an error.
    Error(String),
}

/// Which 03 §6 pattern a sibling matched. All three are handled identically (the header's
/// `vault_id` decides); the kind is only logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConflictKind {
    /// `<name> (<host>'s conflicted copy <date>).vault/`
    Dropbox,
    /// `<name> N.vault/`, N ≥ 2
    ICloud,
    /// Any other `*.vault/`.
    Generic,
}

/// Case-insensitive name equality (Unicode lowercase, like the default APFS volume). Not
/// normalization-insensitive: NFC and NFD spellings of the same name differ here.
pub(crate) fn same_name(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

/// Classify an entry name in the package's parent directory against the package's name. `None`
/// for our package itself and for anything that is not a candidate (hidden, non-`.vault`).
pub(crate) fn classify(file: &str, primary: &str) -> Option<ConflictKind> {
    if file.starts_with('.') || same_name(file, primary) {
        return None;
    }
    let lower = file.to_lowercase();
    let stem = lower.strip_suffix(".vault")?;
    let name = primary.to_lowercase();
    let name = name.strip_suffix(".vault").unwrap_or(&name).to_owned();
    Some(pattern_kind(stem, &name))
}

/// Whether a file name directly inside our package is a per-file conflicted copy candidate of
/// `vault.bin` (03 §6): `vault*.bin` other than `vault.bin` itself, not hidden. Dropbox,
/// Google Drive and Syncthing sync the package's files individually and conflict on the file.
pub(crate) fn classify_inner(file: &str) -> Option<ConflictKind> {
    if file.starts_with('.') || same_name(file, VAULT_FILE_NAME) {
        return None;
    }
    let lower = file.to_lowercase();
    let stem = lower.strip_suffix(".bin")?;
    stem.starts_with("vault")
        .then(|| pattern_kind(stem, "vault"))
}

/// Which 03 §6 pattern `stem` (lowercase, extension removed) matches for the lowercase base
/// name `name`.
fn pattern_kind(stem: &str, name: &str) -> ConflictKind {
    if let Some(rest) = stem.strip_prefix(&format!("{name} ")) {
        // Dropbox: "(<host>'s conflicted copy <date>)"; the apostrophe may be typographic.
        if rest.starts_with('(') && rest.ends_with(')') && rest.contains("conflicted copy") {
            return ConflictKind::Dropbox;
        }
        // iCloud: " 2", " 3", ...
        if !rest.is_empty()
            && rest.bytes().all(|b| b.is_ascii_digit())
            && rest.parse::<u64>().is_ok_and(|n| n >= 2)
        {
            return ConflictKind::ICloud;
        }
    }
    ConflictKind::Generic
}

/// Owns the debouncer; dropping it stops both notify threads.
pub(crate) struct Watcher {
    _debouncer: Debouncer<RecommendedWatcher, NoCache>,
    pub(crate) signals: Receiver<WatchSignal>,
}

impl Watcher {
    /// Watch the package's parent directory recursively, then queue every existing candidate
    /// sibling once so conflicted packages created while we were not running are seen too.
    pub(crate) fn start(package: &Path) -> Result<Self, SyncError> {
        let parent = parent_dir(package).to_owned();
        let package_name = package
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // FSEvents reports resolved paths (/private/var/... for /var/...), so match events
        // against both spellings of each directory.
        let canonical = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_owned());
        let (tx, signals) = crossbeam_channel::unbounded();

        let classifier = Classifier {
            package: [package.to_owned(), canonical(package)],
            parent: [parent.clone(), canonical(&parent)],
            package_name: package_name.clone(),
            tx: tx.clone(),
        };
        let mut debouncer = new_debouncer_opt::<_, RecommendedWatcher, _>(
            DEBOUNCE,
            None,
            move |res: DebounceEventResult| classifier.handle(res),
            NoCache,
            notify::Config::default(),
        )
        .map_err(|e| SyncError::Watch(e.to_string()))?;
        debouncer
            .watch(&parent, RecursiveMode::Recursive)
            .map_err(|e| SyncError::Watch(e.to_string()))?;
        // Scan only once events are flowing, so a package created in between is not missed
        // (seeing it twice is harmless: poll dedupes and absorption is idempotent).
        scan_candidates(&parent, package, &package_name, &tx);
        tracing::info!(package = %package.display(), "watching vault package");
        Ok(Self {
            _debouncer: debouncer,
            signals,
        })
    }
}

/// Every candidate sibling of the package (named `package_name`) currently in `dir`, and
/// every per-file candidate inside `package`.
fn scan_candidates(dir: &Path, package: &Path, package_name: &str, tx: &Sender<WatchSignal>) {
    let send_matching = |d: &Path, matches: &dyn Fn(&str) -> bool| {
        let Ok(entries) = fs::read_dir(d) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name) = name.to_str()
                && matches(name)
            {
                let _ = tx.send(WatchSignal::CandidateConflict(d.join(name)));
            }
        }
    };
    send_matching(dir, &|n| classify(n, package_name).is_some());
    send_matching(package, &|n| classify_inner(n).is_some());
}

/// Where an event path lies relative to the package.
#[derive(Debug, PartialEq, Eq)]
enum Place<'a> {
    /// `vault.bin`, or the package directory itself (replaced or removed wholesale).
    Primary,
    /// A direct child of the parent directory other than our package, or the `vault.bin` or
    /// an `attachments/` entry inside one; carries the child's name.
    Sibling(&'a str),
    /// A per-file conflict candidate directly inside our package ([`classify_inner`]).
    Inner(&'a str),
    /// Anything else: `attachments/`, `backups/`, tmp files, other paths under the parent.
    Ignored,
}

/// Runs on the debouncer thread.
struct Classifier {
    /// The package path as given and canonicalized.
    package: [PathBuf; 2],
    /// Its parent directory, likewise.
    parent: [PathBuf; 2],
    package_name: String,
    tx: Sender<WatchSignal>,
}

impl Classifier {
    fn place<'a>(&self, path: &'a Path) -> Place<'a> {
        for pkg in &self.package {
            if let Ok(rel) = path.strip_prefix(pkg) {
                let mut parts = rel.components().map(|c| c.as_os_str().to_str());
                return match (parts.next(), parts.next()) {
                    (None, _) => Place::Primary,
                    (Some(Some(f)), None) if same_name(f, VAULT_FILE_NAME) => Place::Primary,
                    (Some(Some(f)), None) if classify_inner(f).is_some() => Place::Inner(f),
                    _ => Place::Ignored,
                };
            }
        }
        let Some(rel) = self.parent.iter().find_map(|d| path.strip_prefix(d).ok()) else {
            return Place::Ignored;
        };
        let mut parts = rel.components().map(|c| c.as_os_str().to_str());
        let (Some(Some(name)), inner, blob, None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Place::Ignored;
        };
        // `X.vault/attachments/<file>` counts too: a deferred absorption waits for blobs.
        let inner_is_vault_file = match (inner, blob) {
            (None, _) => false,
            (Some(Some(f)), None) if same_name(f, VAULT_FILE_NAME) => true,
            (Some(Some(d)), Some(Some(_))) if same_name(d, package::ATTACHMENTS_DIR) => false,
            _ => return Place::Ignored,
        };
        if same_name(name, &self.package_name) {
            if blob.is_some() {
                return Place::Ignored;
            }
            // Case-insensitive volume: another spelling of our own package.
            return if inner.is_none() || inner_is_vault_file {
                Place::Primary
            } else {
                Place::Ignored
            };
        }
        Place::Sibling(name)
    }

    fn handle(&self, res: DebounceEventResult) {
        let events = match res {
            Ok(events) => events,
            Err(errors) => {
                for e in errors {
                    let _ = self.tx.send(WatchSignal::Error(format!("watcher: {e}")));
                }
                return;
            }
        };
        let mut primary = false;
        let mut seen = HashSet::new();
        for event in &events {
            if matches!(event.kind, EventKind::Access(_)) {
                continue;
            }
            if event.need_rescan() {
                primary = true;
                scan_candidates(
                    &self.parent[0],
                    &self.package[0],
                    &self.package_name,
                    &self.tx,
                );
            }
            for path in &event.paths {
                match self.place(path) {
                    Place::Primary => primary = true,
                    Place::Sibling(name) => {
                        if classify(name, &self.package_name).is_some() && seen.insert(name) {
                            let _ = self
                                .tx
                                .send(WatchSignal::CandidateConflict(self.parent[0].join(name)));
                        }
                    }
                    Place::Inner(name) => {
                        if classify_inner(name).is_some() && seen.insert(name) {
                            let _ = self
                                .tx
                                .send(WatchSignal::CandidateConflict(self.package[0].join(name)));
                        }
                    }
                    Place::Ignored => {}
                }
            }
        }
        if primary {
            let _ = self.tx.send(WatchSignal::PrimaryChanged);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_patterns() {
        let p = "Test.vault";
        assert_eq!(
            classify("Test (Chris's conflicted copy 2026-10-29).vault", p),
            Some(ConflictKind::Dropbox)
        );
        assert_eq!(
            classify("test (MacBook’s Conflicted Copy 2026-10-29 (1)).VAULT", p),
            Some(ConflictKind::Dropbox)
        );
        assert_eq!(classify("Test 2.vault", p), Some(ConflictKind::ICloud));
        assert_eq!(classify("test 17.vault", p), Some(ConflictKind::ICloud));
        assert_eq!(classify("Test 1.vault", p), Some(ConflictKind::Generic));
        assert_eq!(classify("Test 0.vault", p), Some(ConflictKind::Generic));
        assert_eq!(classify("other.vault", p), Some(ConflictKind::Generic));
        assert_eq!(classify("Test copy.vault", p), Some(ConflictKind::Generic));
        for not in [
            "Test.vault",
            "test.VAULT",
            ".Test.vault.tmp-0011aabb",
            ".Test 2.vault.icloud",
            "Test.vault.backups",
            "vault.bin",
            "notes.txt",
            "vault",
        ] {
            assert_eq!(classify(not, p), None, "{not}");
        }
    }

    fn classifier() -> (Classifier, Receiver<WatchSignal>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let c = Classifier {
            package: [
                PathBuf::from("/d/Test.vault"),
                PathBuf::from("/private/d/Test.vault"),
            ],
            parent: [PathBuf::from("/d"), PathBuf::from("/private/d")],
            package_name: "Test.vault".to_owned(),
            tx,
        };
        (c, rx)
    }

    #[test]
    fn event_places() {
        let (c, _rx) = classifier();
        for primary in [
            "/d/Test.vault/vault.bin",
            "/private/d/Test.vault/vault.bin",
            "/d/Test.vault/VAULT.BIN",
            "/d/Test.vault",
            "/d/test.VAULT",
        ] {
            assert_eq!(c.place(Path::new(primary)), Place::Primary, "{primary}");
        }
        for ignored in [
            "/d/Test.vault/attachments/00000000000000000000000000000001.bin",
            "/d/Test.vault/attachments",
            "/d/Test.vault/backups/Test-2026-10-28T14-03-11Z.vault.bin",
            "/d/Test.vault/backups/conflict-2026-10-28T14-03-11Z-Test 2.vault/vault.bin",
            "/d/Test.vault/.vault.bin.tmp-0011aabb",
            "/d/Test.vault/.DS_Store",
            "/d/Test.vault/attachments/00000000000000000000000000000001 (Mac's conflicted copy).bin",
            "/d/Test.vault/attachments/00000000000000000000000000000001 2.bin",
            "/d/Test.vault/notes.bin",
            "/d/Test.vault/backups/vault 2.bin",
            "/d/Test 2.vault/attachments",
            "/d/Test 2.vault/attachments/x/y.bin",
            "/d/Test 2.vault/backups",
            "/d/Test 2.vault/backups/x.vault.bin",
            "/d/test.vault/attachments/00000000000000000000000000000001.bin",
            "/d/sub/Test 2.vault",
            "/d",
            "/elsewhere/Test 2.vault",
        ] {
            assert_eq!(c.place(Path::new(ignored)), Place::Ignored, "{ignored}");
        }
        for sibling in [
            "/private/d/Test 2.vault",
            "/d/Test 2.vault/vault.bin",
            "/d/Test 2.vault/Vault.bin",
            "/d/Test 2.vault/attachments/00000000000000000000000000000001.bin",
        ] {
            assert_eq!(
                c.place(Path::new(sibling)),
                Place::Sibling("Test 2.vault"),
                "{sibling}"
            );
        }
        for (inner, name) in [
            (
                "/d/Test.vault/vault (Mac's conflicted copy 2026-10-30).bin",
                "vault (Mac's conflicted copy 2026-10-30).bin",
            ),
            ("/private/d/Test.vault/vault 2.bin", "vault 2.bin"),
            ("/d/Test.vault/Vault 3.BIN", "Vault 3.BIN"),
        ] {
            assert_eq!(c.place(Path::new(inner)), Place::Inner(name), "{inner}");
        }
    }

    #[test]
    fn inner_conflict_patterns() {
        assert_eq!(
            classify_inner("vault (Chris's conflicted copy 2026-10-30).bin"),
            Some(ConflictKind::Dropbox)
        );
        assert_eq!(classify_inner("vault 2.bin"), Some(ConflictKind::ICloud));
        assert_eq!(classify_inner("VAULT 12.BIN"), Some(ConflictKind::ICloud));
        assert_eq!(
            classify_inner("vault-copy.bin"),
            Some(ConflictKind::Generic)
        );
        for not in [
            "vault.bin",
            "Vault.BIN",
            ".vault.bin.tmp-0011aabb",
            ".vault 2.bin",
            "vault 2.bin.tmp",
            "notes.bin",
            "attachments",
        ] {
            assert_eq!(classify_inner(not), None, "{not}");
        }
    }

    #[test]
    fn non_ascii_and_spaced_names() {
        let p = "Ärzte Tresor.vault";
        assert_eq!(classify("ärzte tresor.VAULT", p), None);
        assert_eq!(
            classify("ÄRZTE TRESOR 2.vault", p),
            Some(ConflictKind::ICloud)
        );
        assert_eq!(
            classify("Ärzte Tresor (Mac’s conflicted copy 2026-10-30).vault", p),
            Some(ConflictKind::Dropbox)
        );
        assert!(same_name("Ärzte Tresor.vault", "ärzte tresor.vault"));
        assert!(!same_name("Ärzte.vault", "Arzte.vault"));
    }
}
