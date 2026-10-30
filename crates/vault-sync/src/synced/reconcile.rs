//! Reacting to external changes (03 §3) and conflicted packages (03 §6).
//!
//! Everything here runs on the caller's thread from [`SyncedVault::poll`] or `unlock`; the
//! watcher thread only queues [`WatchSignal`]s (see the crate docs).
//!
//! The vault key used to open external versions is exported from the in-memory vault at the
//! moment of use and dropped (zeroized) right after, rather than cached: an `edit` closure can
//! rotate the key (`rotate_vault_key`), and a cached copy would then be stale. While locked
//! there is no key at all.

use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use vault_core::{LockedVault, UnlockedVault, Uuid, VaultError};

use super::{DOWNLOAD_TIMEOUT, SyncedVault, fingerprint};
use crate::attachments;
use crate::backup;
use crate::cloud::CloudError;
use crate::error::{SaveBlocked, SyncError};
use crate::event::SyncEvent;
use crate::package;
use crate::watch::{ConflictKind, WatchSignal, Watcher, classify, classify_inner};

/// Which report was last made for a sibling `*.vault` (see `report_sibling_once`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SiblingReport {
    /// A different vault: [`SyncEvent::ForeignVault`].
    Foreign,
    /// Our vault, but it does not open with our key: [`SyncEvent::Error`].
    Unmergeable,
}

impl SyncedVault {
    /// Start watching the vault package's parent directory recursively, debounced by
    /// [`crate::DEBOUNCE`] (03 §1, §3): `vault.bin` and sibling `*.vault` packages count;
    /// `attachments/`, `backups/` and everything else is ignored. Existing `*.vault` siblings are queued once, so
    /// conflicted packages created while the app was not running are picked up by the first
    /// [`poll`]. A no-op if already watching. Nothing is processed until [`poll`] is called.
    ///
    /// [`poll`]: SyncedVault::poll
    pub fn start_watching(&mut self) -> Result<(), SyncError> {
        if self.watcher.is_none() {
            self.watcher = Some(Watcher::start(&self.path)?);
        }
        Ok(())
    }

    /// Stop watching and discard queued signals. Dropping the debouncer only sets its stop
    /// flag; it does not join, so its threads wind down shortly after this returns (any signal
    /// they still send goes nowhere).
    pub fn stop_watching(&mut self) {
        self.watcher = None;
    }

    pub fn is_watching(&self) -> bool {
        self.watcher.is_some()
    }

    /// Process every queued watcher signal on this thread: the primary first (03 §3), then
    /// each candidate conflicted package (03 §6). Outcomes are reported as [`SyncEvent`]s,
    /// never as errors. Returns the number of signals drained (0 when not watching). Call it
    /// from the app's tick.
    pub fn poll(&mut self) -> usize {
        let Some(watcher) = &self.watcher else {
            return 0;
        };
        let signals: Vec<WatchSignal> = watcher.signals.try_iter().collect();
        let mut primary = false;
        let mut conflicts: Vec<PathBuf> = Vec::new();
        for signal in &signals {
            match signal {
                WatchSignal::PrimaryChanged => primary = true,
                WatchSignal::CandidateConflict(p) => {
                    if !conflicts.contains(p) {
                        conflicts.push(p.clone());
                    }
                }
                WatchSignal::Error(msg) => {
                    tracing::warn!(error = %msg, "watcher error");
                    self.emit(SyncEvent::Error(msg.clone()));
                }
            }
        }
        if primary && self.reconcile_primary_reporting() {
            self.dirty = true;
            if let Err(e) = self.save() {
                self.emit_error(e);
            }
        }
        for path in conflicts {
            self.on_candidate_conflict(&path);
        }
        signals.len()
    }

    /// 03 §3 steps 1-6 for `<name>.vault/vault.bin`. Returns `true` when ours now holds something the
    /// file lacks, i.e. the caller must write (`poll` saves; `save` is about to).
    ///
    /// `Err` only when the primary could not be read (cloud timeout, I/O); `CloudUnavailable`
    /// is emitted for the former. `save` propagates it rather than overwriting a version it
    /// has not merged.
    pub(super) fn reconcile_primary(&mut self) -> Result<bool, SyncError> {
        let Some(bytes) = self.read_primary_if_changed()? else {
            return Ok(false);
        };
        let Some(theirs) = self.vet_primary(&bytes) else {
            return Ok(false);
        };
        // Step 5: locked. The on-disk copy becomes what the next unlock opens; the last
        // verified copy is kept in case this one turns out tampered.
        if self.unlocked.is_none() {
            self.replace_locked_unverified(theirs);
            self.emit(SyncEvent::ChangedWhileLocked);
            return Ok(false);
        }
        // Step 6.
        Ok(match self.open_with_current_key(&theirs) {
            Ok(opened) => {
                self.key_mismatch = false;
                self.locked = theirs;
                self.locked_fallback = None;
                self.merge_in(opened)
            }
            Err(VaultError::WrongPassword) => {
                tracing::warn!(path = %self.file.display(), "on-disk vault does not open with our key");
                // `unlock(password)` re-opens exactly this version.
                self.replace_locked_unverified(theirs);
                self.key_mismatch = true;
                self.emit(SyncEvent::KeyMismatch);
                false
            }
            // Tampered, or anything else that fails after the parse (e.g. a malformed
            // decrypted record): the file is unusable, ours wins.
            Err(e) => {
                tracing::warn!(error = %e, "primary failed its integrity check");
                self.mark_corrupt();
                false
            }
        })
    }

    /// `reconcile_primary` for callers that report rather than propagate (poll, unlock).
    fn reconcile_primary_reporting(&mut self) -> bool {
        match self.reconcile_primary() {
            Ok(need_write) => need_write,
            // Already reported as CloudUnavailable.
            Err(SyncError::Cloud(_)) => false,
            Err(e) => {
                self.emit_error(e);
                false
            }
        }
    }

    /// Steps 1-2 (after `ensure_downloaded`): the primary's bytes if they differ from what we
    /// last wrote or read, recording them as seen. `None` when unchanged, missing or
    /// unavailable (events emitted as needed).
    fn read_primary_if_changed(&mut self) -> Result<Option<Vec<u8>>, SyncError> {
        if let Err(e) = self.hooks.ensure_downloaded(&self.file, DOWNLOAD_TIMEOUT) {
            self.cloud_unavailable(&self.file.clone(), &e);
            return Err(e.into());
        }
        // Step 1: (mtime, size) pre-check against our own last write.
        let meta = match fs::metadata(&self.file) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // Mid-replace by another writer, or deleted; the next event will tell.
                tracing::debug!(path = %self.file.display(), "primary missing");
                return Ok(None);
            }
            Err(e) => return Err(SyncError::io(&self.file, e)),
        };
        if let Some(lw) = self.last_written
            && lw.size == meta.len()
            && lw.mtime.is_some()
            && lw.mtime == meta.modified().ok()
        {
            return Ok(None);
        }
        // Step 2: hash check.
        let bytes = match fs::read(&self.file) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(SyncError::io(&self.file, e)),
        };
        let unchanged = self
            .last_written
            .is_some_and(|lw| lw.hash == *blake3::hash(&bytes).as_bytes());
        // Either way this version has now been seen: refresh the stat so repeated events for
        // the same bytes stop at step 1.
        self.last_written = Some(fingerprint(&self.file, &bytes));
        Ok((!unchanged).then_some(bytes))
    }

    /// Steps 3-4 plus the save-block bookkeeping: the parsed vault if it is a valid file of
    /// this vault in a supported format (which also lifts any [`SaveBlocked`]).
    fn vet_primary(&mut self, bytes: &[u8]) -> Option<LockedVault> {
        match LockedVault::parse(bytes) {
            Err(VaultError::UnsupportedVersion(v)) => {
                // Written by a newer build: never overwrite it (that would downgrade the
                // other device's file), and unlike corruption do not schedule a rewrite.
                tracing::warn!(version = v, "primary written by a newer format version");
                let blocked = SaveBlocked::NewerVersion(v);
                self.save_blocked = Some(blocked);
                self.emit(SyncEvent::Error(blocked.to_string()));
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "primary is unreadable; keeping in-memory state");
                self.mark_corrupt();
                None
            }
            Ok(v) if v.vault_id() != self.locked.vault_id() => {
                tracing::warn!(path = %self.file.display(), "primary now holds a different vault");
                self.save_blocked = Some(SaveBlocked::ForeignVault);
                self.emit(SyncEvent::ForeignVault);
                None
            }
            Ok(v) => {
                if let Some(was) = self.save_blocked.take() {
                    tracing::info!(?was, "valid primary is back; saving allowed again");
                }
                Some(v)
            }
        }
    }

    /// `locked` becomes a version not yet verified; keep the last verified one as fallback.
    fn replace_locked_unverified(&mut self, theirs: LockedVault) {
        let prev = std::mem::replace(&mut self.locked, theirs);
        if self.locked_fallback.is_none() {
            self.locked_fallback = Some(prev);
        }
    }

    /// 03 §3 step 6b-d: merge `theirs` into ours and report. Returns whether a write is needed:
    /// when ours changed (step 6c) **or** when the disk copy lacks something ours has.
    ///
    /// The second case is not in the spec but is required for convergence: if the other device
    /// overwrote our newer state (say our later delete) with its older one, ours wins every
    /// item, "ours changed" is false, and without a write the other device would never see
    /// our state. Detected by merging ours back into the opened disk copy (merge is
    /// commutative, so that is exactly "would the file change").
    fn merge_in(&mut self, mut theirs: UnlockedVault) -> bool {
        let Some(ours) = self.unlocked.as_mut() else {
            return false;
        };
        let report = match ours.merge_from(&theirs) {
            Ok(r) => r,
            Err(e) => {
                self.emit_error(e.into());
                return false;
            }
        };
        let disk_behind = match theirs.merge_from(ours) {
            Ok(r) => r.changed(),
            Err(e) => {
                self.emit_error(e.into());
                return false;
            }
        };
        tracing::debug!(?report, "merged external change");
        self.emit(SyncEvent::Merged(report));
        report.changed() || disk_behind
    }

    /// 03 §6 for a candidate: a sibling `*.vault` package, or a per-file copy of `vault.bin`
    /// inside our package.
    fn on_candidate_conflict(&mut self, path: &Path) {
        if path.parent() == Some(self.path.as_path()) {
            self.on_file_conflict(path);
        } else {
            self.on_package_conflict(path);
        }
    }

    /// 03 §6 for `<pkg>/vault 2.bin`, `<pkg>/vault (… conflicted copy …).bin`, …
    fn on_file_conflict(&mut self, path: &Path) {
        let Some(kind) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(classify_inner)
        else {
            return;
        };
        match fs::symlink_metadata(path) {
            Ok(m) if m.is_file() => {}
            _ => {
                self.sibling_reports.remove(path);
                return;
            }
        }
        let Some(opened) = self.open_conflict(path, path, kind) else {
            return;
        };
        if !self.merge_conflict(&opened) {
            return;
        }
        match backup::absorb_conflict_file(&self.path, path, SystemTime::now()) {
            Ok(dst) => {
                self.sibling_reports.remove(path);
                self.emit(SyncEvent::ConflictAbsorbed(dst));
            }
            Err(e) => self.emit_error(e),
        }
    }

    /// 03 §6 for a `*.vault` sibling package.
    fn on_package_conflict(&mut self, path: &Path) {
        let Some(kind) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| classify(n, &self.path.file_name()?.to_string_lossy()))
        else {
            return;
        };
        match fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() => {}
            // Gone (we or another device already moved it), or not a package (a plain file is
            // the unsupported single-file layout).
            _ => {
                self.sibling_reports.remove(path);
                return;
            }
        }
        let inner = package::vault_file(path);
        // A provider may create the directory before its contents arrive (the arrival of
        // `vault.bin` fires its own event); asking it to download a file it does not know
        // could block for the whole timeout.
        if fs::symlink_metadata(&inner).is_err() && !self.hooks.is_evicted(&inner) {
            if kind != ConflictKind::Generic {
                // Blobs that arrived after the package was absorbed (or before its
                // `vault.bin`): take the ones we lack. The remnant stays where it is: a
                // `vault.bin` arriving later must still find it there to be merged.
                match self.copy_missing_blobs(path) {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!(path = %path.display(), copied = n, "copied blobs from a conflicted package without vault.bin")
                    }
                    Err(SyncError::Cloud(e)) => self.cloud_unavailable(path, &e),
                    Err(e) => self.emit_error(e),
                }
            }
            tracing::debug!(path = %path.display(), "candidate package has no vault.bin");
            return;
        }
        let Some(opened) = self.open_conflict(path, &inner, kind) else {
            return;
        };
        // Blobs first, so a merged reference never reaches disk ahead of its blob. On failure
        // the package stays where it is and is retried on its next event or unlock.
        match self.copy_missing_blobs(path) {
            Ok(0) => {}
            Ok(n) => {
                tracing::info!(path = %path.display(), copied = n, "copied attachment blobs from conflicted package")
            }
            Err(SyncError::Cloud(e)) => return self.cloud_unavailable(path, &e),
            Err(e) => return self.emit_error(e),
        }
        if !self.merge_conflict(&opened) {
            return;
        }
        // A blob the package's items reference may still be arriving inside it: moving the
        // package now would strand it. Keep the package until the blob shows up (its arrival
        // is an event for this package).
        if let Some(id) = self.blob_missing_both_sides(&opened) {
            tracing::info!(path = %path.display(), attachment = %id, "conflicted package merged; waiting for its blobs before moving it");
            return;
        }
        // Steps 4-5.
        match backup::absorb_conflict_package(&self.path, path, SystemTime::now()) {
            Ok(dst) => {
                self.sibling_reports.remove(path);
                self.emit(SyncEvent::ConflictAbsorbed(dst));
            }
            Err(e) => self.emit_error(e),
        }
    }

    /// Steps 1-2 for the conflicted vault file `inner` of candidate `path`: read, parse, check
    /// the vault id, defer while locked, open with our key. `None` (after reporting as
    /// needed) when there is nothing to merge now.
    fn open_conflict(
        &mut self,
        path: &Path,
        inner: &Path,
        kind: ConflictKind,
    ) -> Option<UnlockedVault> {
        let read = match self.read_parsed(inner) {
            Ok(Some(r)) => r,
            Ok(None) => return None,
            Err(SyncError::Cloud(e)) => {
                self.cloud_unavailable(inner, &e);
                return None;
            }
            Err(e) => {
                self.emit_error(e);
                return None;
            }
        };
        let hash = *blake3::hash(&read.bytes).as_bytes();
        // Step 1. An unparseable file (perhaps still arriving) is not ours to judge; leave it
        // alone until its next event.
        let theirs = match read.parsed {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "ignoring unreadable conflict candidate");
                return None;
            }
        };
        if theirs.vault_id() != self.locked.vault_id() {
            tracing::info!(path = %path.display(), "a different vault sits beside ours");
            self.report_sibling_once(path, hash, SiblingReport::Foreign, SyncEvent::ForeignVault);
            return None;
        }
        // Step 2: no key while locked; defer.
        if self.unlocked.is_none() {
            if !self.pending_conflicts.iter().any(|p| p == path) {
                self.pending_conflicts.push(path.to_owned());
            }
            tracing::info!(path = %path.display(), ?kind, "conflicted copy queued until unlock");
            return None;
        }
        match self.open_with_current_key(&theirs) {
            Ok(v) => Some(v),
            Err(e) => {
                // An older key (we rotated since), or damage. Leave it for the user.
                tracing::warn!(path = %path.display(), error = %e, "conflicted copy does not open with our key");
                let event = SyncEvent::Error(format!("could not merge {}: {e}", path.display()));
                self.report_sibling_once(path, hash, SiblingReport::Unmergeable, event);
                None
            }
        }
    }

    /// Step 3: merge `opened` into ours and save. `false` (reported) on failure; the copy
    /// must then stay where it is.
    fn merge_conflict(&mut self, opened: &UnlockedVault) -> bool {
        let Some(ours) = self.unlocked.as_mut() else {
            return false;
        };
        match ours.merge_from(opened) {
            Ok(report) if report.changed() => self.dirty = true,
            Ok(_) => {}
            Err(e) => {
                self.emit_error(e.into());
                return false;
            }
        }
        if let Err(e) = self.save() {
            self.emit_error(e);
            return false;
        }
        true
    }

    /// An attachment that `theirs` references and our merged vault still references, whose
    /// blob is in neither our `attachments/` nor (after `copy_missing_blobs`) theirs.
    fn blob_missing_both_sides(&self, theirs: &UnlockedVault) -> Option<Uuid> {
        let ours = self.unlocked.as_ref()?;
        let merged: HashSet<Uuid> = ours.attachment_ids().collect();
        theirs
            .attachment_ids()
            .filter(|id| merged.contains(id))
            .find(|&id| {
                let local = attachments::blob_path(&self.path, id);
                fs::symlink_metadata(&local).is_err() && !self.hooks.is_evicted(&local)
            })
    }

    /// Emit `event` for `path` unless the same report was already made for the same bytes.
    fn report_sibling_once(
        &mut self,
        path: &Path,
        hash: [u8; 32],
        kind: SiblingReport,
        event: SyncEvent,
    ) {
        if self.sibling_reports.get(path) == Some(&(hash, kind)) {
            tracing::debug!(path = %path.display(), ?kind, "already reported; not repeating");
            return;
        }
        self.sibling_reports.insert(path.to_owned(), (hash, kind));
        self.emit(event);
    }

    /// Work deferred while locked: rewrite a corrupt primary and absorb queued copies.
    pub(super) fn after_unlock(&mut self) {
        if std::mem::take(&mut self.rewrite_on_unlock) {
            self.dirty = true;
            self.dirty_from_corrupt = true;
        }
        for path in std::mem::take(&mut self.pending_conflicts) {
            self.on_candidate_conflict(&path);
        }
    }

    /// Before unlocking: re-read the primary if it differs from what we hold, so the unlock
    /// opens the on-disk version (03 §3 step 5) even without a watcher. Returns whether the
    /// primary could be read (failures are reported as events).
    pub(super) fn refresh_locked_from_disk(&mut self) -> bool {
        debug_assert!(self.unlocked.is_none());
        // On failure the unlock opens the copy we already hold; nothing is written.
        match self.reconcile_primary() {
            // Read, unless it was missing (or is no longer a regular file): then what is on
            // disk is unknown.
            Ok(_) => fs::metadata(&self.file).is_ok_and(|m| m.is_file()),
            // Already reported as CloudUnavailable.
            Err(SyncError::Cloud(_)) => false,
            Err(e) => {
                self.emit_error(e);
                false
            }
        }
    }

    /// After `KeyMismatch`, the user re-entered a credential that opens the on-disk vault:
    /// make that vault (its header, slots and key) ours, folding the old in-memory items in.
    pub(super) fn adopt_reverified(&mut self, mut theirs: UnlockedVault) {
        let Some(ours) = self.unlocked.take() else {
            return;
        };
        theirs.set_device_id(self.device_id);
        let report = match theirs.merge_from(&ours) {
            Ok(r) => r,
            Err(e) => {
                self.unlocked = Some(ours);
                return self.emit_error(e.into());
            }
        };
        let was_dirty = self.dirty;
        self.install(theirs);
        self.locked_fallback = None;
        // Our items that the disk lacked still need writing.
        self.dirty = was_dirty || report.changed();
        tracing::warn!("adopted the on-disk vault's keys after a key mismatch");
        self.emit(SyncEvent::KeyRotatedOnDisk);
        self.emit(SyncEvent::Merged(report));
    }

    fn open_with_current_key(&self, theirs: &LockedVault) -> Result<UnlockedVault, VaultError> {
        let Some(ours) = self.unlocked.as_ref() else {
            return Err(VaultError::WrongPassword);
        };
        let key = ours.export_vault_key();
        theirs.unlock_with_key(&key, self.device_id)
    }

    /// 03 §3 step 3: report, keep in-memory state, and make the next save rewrite the file.
    pub(super) fn mark_corrupt(&mut self) {
        if self.unlocked.is_some() {
            self.dirty = true;
            self.dirty_from_corrupt = true;
        } else {
            self.rewrite_on_unlock = true;
        }
        self.emit(SyncEvent::CorruptOnDisk);
    }

    fn cloud_unavailable(&self, path: &Path, e: &CloudError) {
        tracing::warn!(path = %path.display(), error = %e, "cloud file unavailable");
        self.emit(SyncEvent::CloudUnavailable);
    }

    fn emit_error(&self, e: SyncError) {
        // Every cloud failure is reported as CloudUnavailable where it happens (e.g. the
        // pre-merge in a `save` called from `poll`); do not repeat it as an Error.
        if let SyncError::Cloud(e) = &e {
            tracing::debug!(error = %e, "cloud error already reported");
            return;
        }
        tracing::warn!(error = %e, "sync error");
        self.emit(SyncEvent::Error(e.to_string()));
    }
}
