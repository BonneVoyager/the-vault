//! The filesystem watcher (03 §3) and conflicted-copy name patterns (03 §6).
//!
//! Threading: `notify-debouncer-full` owns a watcher thread and a debounce thread. Our event
//! handler runs on the debounce thread and does nothing but classify paths and send
//! [`WatchSignal`]s down a channel. It never touches `SyncedVault`, reads no file contents and
//! holds no key. All reading, parsing, merging and writing happens later on the caller's thread
//! in `SyncedVault::poll`, so `SyncedVault` needs no locking.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};
use notify::{EventKind, RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, Debouncer, RecommendedCache, new_debouncer};

use crate::atomic::parent_dir;
use crate::error::SyncError;

/// Debounce window (03 §3).
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// What the watcher thread tells `SyncedVault::poll`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchSignal {
    /// Something happened to `<name>.vault`.
    PrimaryChanged,
    /// A `*.vault` sibling appeared or changed; it may be a conflicted copy (03 §6).
    CandidateConflict(PathBuf),
    /// The watcher itself reported an error.
    Error(String),
}

/// Which 03 §6 pattern a sibling matched. All three are handled identically (the header's
/// `vault_id` decides); the kind is only logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConflictKind {
    /// `<name> (<host>'s conflicted copy <date>).vault`
    Dropbox,
    /// `<name> N.vault`, N ≥ 2
    ICloud,
    /// Any other `*.vault`.
    Generic,
}

/// Classify a file name in `<dir>` against the primary's file name. `None` for the primary
/// itself and for anything that is not a candidate (hidden files, our tmp files, non-`.vault`).
/// Matching is ASCII case-insensitive, like the default APFS volume.
pub(crate) fn classify(file: &str, primary: &str) -> Option<ConflictKind> {
    if file.starts_with('.') || file.eq_ignore_ascii_case(primary) {
        return None;
    }
    let lower = file.to_ascii_lowercase();
    let stem = lower.strip_suffix(".vault")?;
    let name = primary.to_ascii_lowercase();
    let name = name.strip_suffix(".vault").unwrap_or(&name).to_owned();

    if let Some(rest) = stem.strip_prefix(&format!("{name} ")) {
        // Dropbox: "(<host>'s conflicted copy <date>)"; the apostrophe may be typographic.
        if rest.starts_with('(') && rest.ends_with(')') && rest.contains("conflicted copy") {
            return Some(ConflictKind::Dropbox);
        }
        // iCloud: " 2", " 3", ...
        if !rest.is_empty()
            && rest.bytes().all(|b| b.is_ascii_digit())
            && rest.parse::<u64>().is_ok_and(|n| n >= 2)
        {
            return Some(ConflictKind::ICloud);
        }
    }
    Some(ConflictKind::Generic)
}

/// Owns the debouncer; dropping it stops both notify threads.
pub(crate) struct Watcher {
    _debouncer: Debouncer<RecommendedWatcher, RecommendedCache>,
    pub(crate) signals: Receiver<WatchSignal>,
}

impl Watcher {
    /// Watch the directory containing `primary`, non-recursively, then queue every existing
    /// candidate sibling once so copies created while we were not running are seen too.
    pub(crate) fn start(primary: &Path) -> Result<Self, SyncError> {
        let dir = parent_dir(primary).to_owned();
        let primary_name = primary
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // FSEvents reports resolved paths (/private/var/... for /var/...), so match the
        // event's parent against both spellings of the directory.
        let canonical = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        let (tx, signals) = crossbeam_channel::unbounded();

        let classifier = Classifier {
            dir: dir.clone(),
            canonical,
            primary_name: primary_name.clone(),
            tx: tx.clone(),
        };
        let mut debouncer = new_debouncer(DEBOUNCE, None, move |res: DebounceEventResult| {
            classifier.handle(res);
        })
        .map_err(|e| SyncError::Watch(e.to_string()))?;
        debouncer
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(|e| SyncError::Watch(e.to_string()))?;
        // Scan only once events are flowing, so a file created in between is not missed
        // (seeing it twice is harmless: poll dedupes and absorption is idempotent).
        scan_candidates(&dir, &primary_name, &tx);
        tracing::info!(dir = %dir.display(), "watching vault directory");
        Ok(Self {
            _debouncer: debouncer,
            signals,
        })
    }
}

/// Every candidate sibling of the primary (named `primary_name`) currently in `dir`.
fn scan_candidates(dir: &Path, primary_name: &str, tx: &Sender<WatchSignal>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if let Some(name) = name.to_str()
            && classify(name, primary_name).is_some()
        {
            let _ = tx.send(WatchSignal::CandidateConflict(dir.join(name)));
        }
    }
}

/// Runs on the debouncer thread.
struct Classifier {
    dir: PathBuf,
    canonical: PathBuf,
    primary_name: String,
    tx: Sender<WatchSignal>,
}

impl Classifier {
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
                scan_candidates(&self.dir, &self.primary_name, &self.tx);
            }
            for path in &event.paths {
                let in_dir = path
                    .parent()
                    .is_some_and(|p| p == self.dir || p == self.canonical);
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !in_dir {
                    continue;
                }
                if name.eq_ignore_ascii_case(&self.primary_name) {
                    primary = true;
                } else if classify(name, &self.primary_name).is_some() && seen.insert(name) {
                    let _ = self
                        .tx
                        .send(WatchSignal::CandidateConflict(self.dir.join(name)));
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
            "notes.txt",
            "vault",
        ] {
            assert_eq!(classify(not, p), None, "{not}");
        }
    }
}
