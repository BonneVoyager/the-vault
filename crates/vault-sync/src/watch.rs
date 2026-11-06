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
//! Every name and path comparison here is normalisation-insensitive (NFC per component, see
//! [`package::nfc`]): a provider may deliver `A\u{308}` where we wrote `\u{c4}`.
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TrySendError};
use notify::{EventKind, RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, Debouncer, NoCache, new_debouncer_opt};

use crate::atomic::parent_dir;
use crate::error::SyncError;
use crate::package::{self, VAULT_FILE_NAME, fold_name, strip_prefix_nfc};

/// Debounce window (03 §3).
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// Capacity of the watcher-to-`poll` signal channel. When it is full the watcher thread drops
/// the signal and sets the rescan flag instead, so nothing is lost: the next `poll` treats
/// the primary as changed and rescans for candidates.
pub(crate) const SIGNAL_CAPACITY: usize = 1024;
/// Most conflict candidates queued for `poll` at once. More are not lost: a dropped event
/// requests a rescan, and a rescan that finds more than this pages through them by path.
pub(crate) const MAX_PENDING_CANDIDATES: usize = 256;
/// Most conflict candidates one `poll` processes; the rest stay queued for the next one, so
/// the caller's thread is never held for long by a directory full of candidates.
pub(crate) const CANDIDATES_PER_POLL: usize = 8;

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

/// Case-insensitive name equality (Unicode lowercase, like the default APFS volume), also
/// insensitive to the normalisation form (NFC and NFD spellings of a name are equal).
pub(crate) fn same_name(a: &str, b: &str) -> bool {
    a == b || fold_name(a) == fold_name(b)
}

/// Classify an entry name in the package's parent directory against the package's name. `None`
/// for our package itself and for anything that is not a candidate (hidden, non-`.vault`).
pub(crate) fn classify(file: &str, primary: &str) -> Option<ConflictKind> {
    if file.starts_with('.') || same_name(file, primary) {
        return None;
    }
    let lower = fold_name(file);
    let stem = lower.strip_suffix(".vault")?;
    let name = fold_name(primary);
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
    let lower = fold_name(file);
    let stem = lower.strip_suffix(".bin")?;
    stem.starts_with("vault")
        .then(|| pattern_kind(stem, "vault"))
}

/// Which 03 §6 pattern `stem` (folded by [`fold_name`], extension removed) matches for the
/// folded base name `name`.
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

/// Owns the debouncer; dropping it stops both notify threads. Also holds the candidate
/// queue, which only the caller's thread (`poll`) touches.
pub(crate) struct Watcher {
    _debouncer: Debouncer<RecommendedWatcher, NoCache>,
    pub(crate) signals: Receiver<WatchSignal>,
    /// Set by the watcher thread when a signal could not be queued (channel full) or the OS
    /// asked for a rescan; `poll` then reconciles the primary and rescans for candidates.
    pub(crate) rescan: Arc<AtomicBool>,
    pub(crate) queue: CandidateQueue,
    package: PathBuf,
    parent: PathBuf,
    package_name: String,
}

impl Watcher {
    /// Watch the package's parent directory recursively, then queue the existing candidate
    /// siblings (up to [`MAX_PENDING_CANDIDATES`], the rest page in as the queue drains) so
    /// conflicted packages created while we were not running are seen too.
    pub(crate) fn start(package: &Path) -> Result<Self, SyncError> {
        let parent = parent_dir(package).to_owned();
        let package_name = package
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // FSEvents reports resolved paths (/private/var/... for /var/...), so match events
        // against both spellings of each directory.
        let canonical = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_owned());
        let (tx, signals) = crossbeam_channel::bounded(SIGNAL_CAPACITY);
        let rescan = Arc::new(AtomicBool::new(false));

        let classifier = Classifier {
            package: [package.to_owned(), canonical(package)],
            parent: [parent.clone(), canonical(&parent)],
            package_name: package_name.clone(),
            tx,
            rescan: rescan.clone(),
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
        let mut watcher = Self {
            _debouncer: debouncer,
            signals,
            rescan,
            queue: CandidateQueue::default(),
            package: package.to_owned(),
            parent,
            package_name,
        };
        // Scan only once events are flowing, so a package created in between is not missed
        // (seeing it twice is harmless: the queue dedupes and absorption is idempotent).
        watcher.queue.request_scan();
        watcher.scan_if_due();
        tracing::info!(package = %package.display(), "watching vault package");
        Ok(watcher)
    }

    /// Run the next page of a requested or unfinished scan if the queue is empty.
    pub(crate) fn scan_if_due(&mut self) {
        if !self.queue.scan_due() {
            return;
        }
        let (parent, package, name) = (&self.parent, &self.package, &self.package_name);
        self.queue
            .scan_page(|offer| scan_candidates(parent, package, name, offer));
    }
}

/// Every candidate sibling of the package (named `package_name`) currently in `dir`, and
/// every per-file candidate inside `package`, handed to `offer` one at a time (never
/// collected: the directory may hold any number of entries).
fn scan_candidates(dir: &Path, package: &Path, package_name: &str, offer: &mut dyn FnMut(PathBuf)) {
    let mut send_matching = |d: &Path, matches: &dyn Fn(&str) -> bool| {
        let Ok(entries) = fs::read_dir(d) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name) = name.to_str()
                && matches(name)
            {
                offer(d.join(name));
            }
        }
    };
    send_matching(dir, &|n| classify(n, package_name).is_some());
    send_matching(package, &|n| classify_inner(n).is_some());
}

/// The bounded, deduplicated set of conflict candidates waiting for `poll`, plus the state
/// of a paged scan. Keys are [`package::path_key`]s (NFC), so an event and a scan spelling the
/// same name in NFC and NFD queue it once; candidates are taken in key order.
///
/// Bounds: at most [`MAX_PENDING_CANDIDATES`] entries. A candidate offered while full is
/// dropped and a rescan is requested. A scan runs only once the queue is empty, and keeps
/// only the smallest keys above its cursor that fit; if more matched, the cursor advances
/// and the next page runs when the queue is empty again. So every candidate present on disk
/// is eventually queued, with memory bounded by the cap however many entries the directory
/// holds.
#[derive(Debug, Default)]
pub(crate) struct CandidateQueue {
    pending: BTreeMap<PathBuf, PathBuf>,
    /// A full scan from the start was requested (dropped candidate, rescan signal, start).
    scan_requested: bool,
    /// A scan is in progress: the next page starts after this key (`Some(None)` = from the
    /// start).
    cursor: Option<Option<PathBuf>>,
    /// More candidates than fit were seen (dropped, or left for a later scan page) since
    /// the last [`CandidateQueue::take_overflow_report`].
    overflowed: bool,
    /// The overflow warning was emitted for the current episode (reset once idle).
    overflow_reported: bool,
}

impl CandidateQueue {
    /// Queue `path` unless already queued. `false` if it was dropped because the queue is
    /// full (a rescan is then requested).
    pub(crate) fn push(&mut self, path: PathBuf) -> bool {
        let key = package::path_key(&path);
        if self.pending.contains_key(&key) {
            return true;
        }
        if self.pending.len() >= MAX_PENDING_CANDIDATES {
            self.scan_requested = true;
            self.overflowed = true;
            return false;
        }
        self.pending.insert(key, path);
        true
    }

    /// The next candidate to process, in key order.
    pub(crate) fn pop(&mut self) -> Option<PathBuf> {
        let next = self.pending.pop_first().map(|(_, p)| p);
        if self.is_idle() {
            self.overflow_reported = false;
        }
        next
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn request_scan(&mut self) {
        self.scan_requested = true;
    }

    /// Whether the overflow warning should be emitted now: `true` once per episode (from the
    /// first overflow until the queue is empty with no scan outstanding).
    pub(crate) fn take_overflow_report(&mut self) -> bool {
        std::mem::take(&mut self.overflowed)
            && !std::mem::replace(&mut self.overflow_reported, true)
    }

    fn is_idle(&self) -> bool {
        self.pending.is_empty() && !self.scan_requested && self.cursor.is_none()
    }

    /// A scan page may run now: one is requested or unfinished, and the queue is empty.
    pub(crate) fn scan_due(&self) -> bool {
        self.pending.is_empty() && (self.scan_requested || self.cursor.is_some())
    }

    /// Run one page: `visit` offers every matching path; the smallest keys above the cursor
    /// (up to the cap) are queued. Returns whether more matched than fit.
    pub(crate) fn scan_page(&mut self, visit: impl FnOnce(&mut dyn FnMut(PathBuf))) -> bool {
        let after = match self.cursor.take() {
            Some(after) => after,
            None => {
                self.scan_requested = false;
                None
            }
        };
        let room = MAX_PENDING_CANDIDATES.saturating_sub(self.pending.len());
        let mut page: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
        let mut capped = false;
        visit(&mut |path| {
            let key = package::path_key(&path);
            if after.as_ref().is_some_and(|a| key <= *a) || self.pending.contains_key(&key) {
                return;
            }
            page.insert(key, path);
            if page.len() > room {
                page.pop_last();
                capped = true;
            }
        });
        if capped {
            self.cursor = Some(page.last_key_value().map(|(k, _)| k.clone()).or(after));
            self.overflowed = true;
        }
        self.pending.extend(page);
        capped
    }
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
    /// Shared with [`Watcher::rescan`].
    rescan: Arc<AtomicBool>,
}

impl Classifier {
    /// Queue `signal` without blocking; if the channel is full, drop it and ask `poll` for a
    /// rescan (which also reconciles the primary), so the drop loses nothing.
    fn send(&self, signal: WatchSignal) {
        match self.tx.try_send(signal) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                if !self.rescan.swap(true, Ordering::AcqRel) {
                    tracing::warn!("watcher signal queue full; rescanning on the next poll");
                }
            }
        }
    }

    fn place<'a>(&self, path: &'a Path) -> Place<'a> {
        for pkg in &self.package {
            if let Some(rel) = strip_prefix_nfc(path, pkg) {
                let mut parts = rel.components().map(|c| c.as_os_str().to_str());
                return match (parts.next(), parts.next()) {
                    (None, _) => Place::Primary,
                    (Some(Some(f)), None) if same_name(f, VAULT_FILE_NAME) => Place::Primary,
                    (Some(Some(f)), None) if classify_inner(f).is_some() => Place::Inner(f),
                    _ => Place::Ignored,
                };
            }
        }
        let Some(rel) = self.parent.iter().find_map(|d| strip_prefix_nfc(path, d)) else {
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
                    self.send(WatchSignal::Error(format!("watcher: {e}")));
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
                // The scan itself runs in `poll`, bounded by the candidate queue.
                self.rescan.store(true, Ordering::Release);
                primary = true;
            }
            for path in &event.paths {
                match self.place(path) {
                    Place::Primary => primary = true,
                    Place::Sibling(name) => {
                        if classify(name, &self.package_name).is_some() && seen.insert(name) {
                            self.send(WatchSignal::CandidateConflict(self.parent[0].join(name)));
                        }
                    }
                    Place::Inner(name) => {
                        if classify_inner(name).is_some() && seen.insert(name) {
                            self.send(WatchSignal::CandidateConflict(self.package[0].join(name)));
                        }
                    }
                    Place::Ignored => {}
                }
            }
        }
        if primary {
            self.send(WatchSignal::PrimaryChanged);
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
            rescan: Arc::default(),
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

    /// `Ärzte` with Ä precomposed (NFC) and decomposed (NFD), under a parent `Café` likewise.
    const NFC_NAME: &str = "\u{c4}rzte.vault";
    const NFD_NAME: &str = "A\u{308}rzte.vault";
    const NFC_DIR: &str = "/d/Caf\u{e9}";
    const NFD_DIR: &str = "/d/Cafe\u{301}";

    /// A package created with NFC names (directory and package).
    fn nfc_classifier() -> (Classifier, Receiver<WatchSignal>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let pkg = PathBuf::from(NFC_DIR).join(NFC_NAME);
        let c = Classifier {
            package: [pkg.clone(), pkg],
            parent: [PathBuf::from(NFC_DIR), PathBuf::from(NFC_DIR)],
            package_name: NFC_NAME.to_owned(),
            tx,
            rescan: Arc::default(),
        };
        (c, rx)
    }

    #[test]
    fn nfd_event_paths_classify_like_nfc() {
        let (c, _rx) = nfc_classifier();
        for dir in [NFC_DIR, NFD_DIR] {
            for primary in [
                format!("{dir}/{NFD_NAME}/vault.bin"),
                format!("{dir}/{NFD_NAME}"),
                format!("{dir}/{NFC_NAME}/vault.bin"),
                format!("{dir}/a\u{308}RZTE.vault/vault.bin"),
            ] {
                assert_eq!(c.place(Path::new(&primary)), Place::Primary, "{primary}");
            }
            let inner = format!("{dir}/{NFD_NAME}/vault 2.bin");
            assert_eq!(c.place(Path::new(&inner)), Place::Inner("vault 2.bin"));
            for ignored in [
                format!("{dir}/{NFD_NAME}/attachments/00000000000000000000000000000001.bin"),
                format!("{dir}/{NFD_NAME}/backups/x.vault.bin"),
            ] {
                assert_eq!(c.place(Path::new(&ignored)), Place::Ignored, "{ignored}");
            }
            let sibling = "A\u{308}rzte 2.vault";
            for path in [
                format!("{dir}/{sibling}"),
                format!("{dir}/{sibling}/vault.bin"),
            ] {
                assert_eq!(c.place(Path::new(&path)), Place::Sibling(sibling), "{path}");
            }
        }
        // Differs by more than normalisation: another directory, another package.
        assert_eq!(
            c.place(Path::new("/d/Cafe/\u{c4}rzte.vault/vault.bin")),
            Place::Ignored
        );
        assert_eq!(
            c.place(Path::new("/d/Caf\u{e9}/Arzte.vault/vault.bin")),
            Place::Sibling("Arzte.vault")
        );
    }

    #[test]
    fn nfd_siblings_match_the_nfc_package_name() {
        assert_eq!(classify(NFD_NAME, NFC_NAME), None);
        assert_eq!(classify(NFC_NAME, NFD_NAME), None);
        assert_eq!(
            classify("A\u{308}rzte 2.vault", NFC_NAME),
            Some(ConflictKind::ICloud)
        );
        assert_eq!(
            classify("\u{c4}rzte 3.vault", NFD_NAME),
            Some(ConflictKind::ICloud)
        );
        assert_eq!(
            classify(
                "A\u{308}rzte (Mac's conflicted copy 2026-10-30).vault",
                NFC_NAME
            ),
            Some(ConflictKind::Dropbox)
        );
        // Not the same name: only the generic "any *.vault" rule applies (the header decides).
        assert_eq!(
            classify("Arzte 2.vault", NFC_NAME),
            Some(ConflictKind::Generic)
        );
        assert_eq!(
            classify("A\u{300}rzte 2.vault", NFC_NAME),
            Some(ConflictKind::Generic)
        );
        assert_eq!(classify("A\u{308}rzte.txt", NFC_NAME), None);
        // `vault.bin` spelled with a decomposed letter cannot occur (ASCII), but `vault 2.bin`
        // with a provider-added suffix still matches whatever form the rest is in.
        assert_eq!(classify_inner("vault 2.bin"), Some(ConflictKind::ICloud));
        assert!(same_name(NFC_NAME, NFD_NAME));
        assert!(same_name("\u{e4}RZTE.vault", NFD_NAME));
        assert!(!same_name("Arzte.vault", NFD_NAME));
    }

    #[test]
    fn handler_sends_signals_for_nfd_events() {
        use notify::event::{CreateKind, ModifyKind};
        use notify_debouncer_full::DebouncedEvent;
        use std::time::Instant;

        let (c, rx) = nfc_classifier();
        let ev = |kind: EventKind, p: String| {
            DebouncedEvent::new(notify::Event::new(kind).add_path(p.into()), Instant::now())
        };
        let modify = EventKind::Modify(ModifyKind::Any);
        let create = EventKind::Create(CreateKind::Folder);
        c.handle(Ok(vec![
            ev(modify, format!("{NFD_DIR}/{NFD_NAME}/vault.bin")),
            ev(create, format!("{NFD_DIR}/A\u{308}rzte 2.vault")),
            ev(create, format!("{NFD_DIR}/Arzte.txt")),
        ]));
        let got: Vec<WatchSignal> = rx.try_iter().collect();
        assert_eq!(
            got,
            [
                WatchSignal::CandidateConflict(PathBuf::from(NFC_DIR).join("A\u{308}rzte 2.vault")),
                WatchSignal::PrimaryChanged,
            ]
        );
    }

    fn cand(i: usize) -> PathBuf {
        PathBuf::from(format!("/d/Test {i:04}.vault"))
    }

    #[test]
    fn queue_dedupes_and_caps() {
        let mut q = CandidateQueue::default();
        assert!(q.push(cand(1)));
        assert!(q.push(cand(1)));
        // The same name in NFD is the same candidate.
        assert!(q.push(PathBuf::from("/d/\u{c4}rzte 2.vault")));
        assert!(q.push(PathBuf::from("/d/A\u{308}rzte 2.vault")));
        assert_eq!(q.len(), 2);
        for i in 2..MAX_PENDING_CANDIDATES {
            assert!(q.push(cand(i)));
        }
        assert_eq!(q.len(), MAX_PENDING_CANDIDATES);
        assert!(!q.take_overflow_report());
        assert!(!q.push(cand(9999)), "pushed past the cap");
        assert_eq!(q.len(), MAX_PENDING_CANDIDATES);
        assert!(q.take_overflow_report());
        assert!(!q.take_overflow_report(), "reported twice in one episode");
        // Not due until the queue is empty.
        assert!(!q.scan_due());
        while q.pop().is_some() {}
        assert!(q.scan_due(), "the drop must request a rescan");
    }

    /// 300 candidates on disk: pages of at most the cap, every one queued exactly once, and
    /// the scan finishes.
    #[test]
    fn paged_scan_covers_every_candidate_once() {
        let all: Vec<PathBuf> = (0..300).rev().map(cand).collect();
        let mut q = CandidateQueue::default();
        q.request_scan();
        let mut seen = Vec::new();
        let mut pages = 0;
        while q.scan_due() {
            pages += 1;
            assert!(pages < 10, "scan does not terminate");
            q.scan_page(|offer| all.iter().cloned().for_each(offer));
            assert!(q.len() <= MAX_PENDING_CANDIDATES);
            while let Some(p) = q.pop() {
                seen.push(p);
            }
        }
        assert_eq!(pages, 2);
        let mut want = all.clone();
        want.sort();
        assert_eq!(seen, want);
        assert!(q.take_overflow_report());
    }

    #[test]
    fn full_channel_drops_and_requests_rescan() {
        let (tx, rx) = crossbeam_channel::bounded(2);
        let rescan = Arc::new(AtomicBool::new(false));
        let c = Classifier {
            package: [
                PathBuf::from("/d/Test.vault"),
                PathBuf::from("/d/Test.vault"),
            ],
            parent: [PathBuf::from("/d"), PathBuf::from("/d")],
            package_name: "Test.vault".to_owned(),
            tx,
            rescan: rescan.clone(),
        };
        c.send(WatchSignal::PrimaryChanged);
        c.send(WatchSignal::PrimaryChanged);
        assert!(!rescan.load(Ordering::Acquire));
        c.send(WatchSignal::CandidateConflict(cand(1)));
        assert!(
            rescan.load(Ordering::Acquire),
            "drop did not request a rescan"
        );
        assert_eq!(rx.try_iter().count(), 2);
    }

    /// An OS "rescan" event no longer scans on the watcher thread; it sets the flag.
    #[test]
    fn need_rescan_event_sets_the_flag() {
        use notify::event::Flag;
        use notify_debouncer_full::DebouncedEvent;
        use std::time::Instant;

        let (c, rx) = classifier();
        let event = notify::Event::new(EventKind::Other).set_flag(Flag::Rescan);
        c.handle(Ok(vec![DebouncedEvent::new(event, Instant::now())]));
        assert!(c.rescan.load(Ordering::Acquire));
        assert_eq!(
            rx.try_iter().collect::<Vec<_>>(),
            [WatchSignal::PrimaryChanged]
        );
    }
}
