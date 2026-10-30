//! [`SyncedVault`]: a vault bound to a package directory (03 §1, §8): open, unlock, edit,
//! atomic save, snapshots and restore. Watching and reconciling external changes live in [`reconcile`].

mod attachments;
mod reconcile;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use crossbeam_channel::{Receiver, Sender};
use vault_core::{
    KdfParams, LockedVault, SecretString, SecretVec, SlotKind, UnlockedVault, Uuid, VaultError,
};

use crate::atomic::{Mode, write_atomic};
use crate::backup::{self, BackupInfo, BackupKind};
use crate::cloud::CloudHooks;
use crate::error::{SaveBlocked, SyncError};
use crate::event::SyncEvent;
use crate::package;
use crate::watch::Watcher;

/// How long `open` waits for the cloud provider to materialise the file (03 §7).
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Fingerprint of the bytes most recently written to (or read from) the primary file, used to
/// recognise our own writes echoing back through the watcher (03 §2 step 6, §3 steps 1-2).
///
/// `hash` (blake3 of the exact bytes) is the authoritative comparison key. `(mtime, size)` is
/// only a fast pre-check; `mtime` is `None` when the file could not be stat'ed after writing,
/// in which case the echo check must go straight to the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastWritten {
    pub mtime: Option<SystemTime>,
    pub size: u64,
    pub hash: [u8; 32],
}

/// Plaintext header facts the unlock screen needs before any credential is entered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedSummary {
    pub vault_id: Uuid,
    /// `(slot id, kind)` in header order; an `Enclave` slot means Touch ID unlock is possible.
    pub slots: Vec<(Uuid, SlotKind)>,
}

/// A vault bound to a package directory on disk.
pub struct SyncedVault {
    /// The `<name>.vault/` package directory.
    path: PathBuf,
    /// `<path>/vault.bin`, the primary file.
    file: PathBuf,
    device_id: Uuid,
    hooks: Arc<dyn CloudHooks>,
    /// The on-disk version as of the last read or write. Unlock always starts from this.
    locked: LockedVault,
    /// `Some` while unlocked. Dropping it zeroizes the key material (vault-core's `Keys`).
    unlocked: Option<UnlockedVault>,
    dirty: bool,
    last_written: Option<LastWritten>,
    /// Behind a mutex so `subscribe` can take `&self` as in 03 §8.
    subscribers: Mutex<Vec<Sender<SyncEvent>>>,
    /// 03 §4 settings. Not persisted here; the app owns persistence.
    backup_enabled: bool,
    retention_multiplier: f32,
    /// Set when an unlocked vault is installed; cleared by the next `save`.
    first_save_after_unlock: bool,
    /// Live item count at the last save (or unlock), for the "count decreased" trigger.
    last_item_count: Option<usize>,
    /// `Some` between `start_watching` and `stop_watching`.
    watcher: Option<Watcher>,
    /// Conflicted copies seen while locked (03 §6 step 2), absorbed at the next unlock.
    pending_conflicts: Vec<PathBuf>,
    /// The primary was found corrupt while locked: mark dirty at unlock so it is rewritten.
    rewrite_on_unlock: bool,
    /// The last triggered snapshot failed; the next save takes one regardless of policy.
    snapshot_retry: bool,
    /// `dirty` is (also) owed to a corrupt primary seen while unlocked; `lock` turns it into
    /// `rewrite_on_unlock`. Cleared by a successful write.
    dirty_from_corrupt: bool,
    /// The on-disk vault no longer opens with our vault key; `save` refuses until `unlock`.
    key_mismatch: bool,
    /// The primary is a newer format or another vault; `save` refuses until a valid file of
    /// this vault is seen again.
    save_blocked: Option<SaveBlocked>,
    /// The last `locked` that was verified (opened, or written by us), kept while `locked`
    /// holds a version not yet verified (changed while locked, or after a key mismatch). If
    /// that version turns out tampered, unlock falls back to this one.
    locked_fallback: Option<LockedVault>,
    /// Last `ForeignVault` / `Error` reported per sibling, with the bytes' hash, so a file
    /// that keeps firing watcher events is reported once until it changes or disappears.
    sibling_reports: HashMap<PathBuf, ([u8; 32], reconcile::SiblingReport)>,
    /// Added to the clock by orphan cleanup. Always zero unless the `test-support` feature is
    /// on (file ages count from ctime, which tests cannot set back).
    prune_clock_offset: Duration,
}

impl fmt::Debug for SyncedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncedVault")
            .field("path", &self.path)
            .field("vault_id", &self.locked.vault_id())
            .field("unlocked", &self.unlocked.is_some())
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

impl SyncedVault {
    /// Create a new vault package at `path` (a directory, conventionally `<name>.vault`, mode
    /// 0700) and write its `vault.bin` (0600) immediately. Refuses an existing path; the parent
    /// directory must exist. The returned vault is unlocked and clean.
    pub fn create(
        path: &Path,
        password: &SecretString,
        kdf: KdfParams,
        device_id: Uuid,
        hooks: Arc<dyn CloudHooks>,
    ) -> Result<Self, SyncError> {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(SyncError::AlreadyExists(path.to_owned())),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(SyncError::io(path, e)),
        }
        kdf.validate()?;
        let vault = UnlockedVault::create(password, kdf, device_id);
        let bytes = vault.serialize();
        let locked = LockedVault::parse(&bytes)?;
        package::create_new_dir(path)?;
        let mut this = Self {
            path: path.to_owned(),
            file: package::vault_file(path),
            device_id,
            hooks,
            locked,
            unlocked: Some(vault),
            dirty: false,
            last_written: None,
            subscribers: Mutex::default(),
            backup_enabled: true,
            retention_multiplier: backup::RETENTION_MULTIPLIER_DEFAULT,
            first_save_after_unlock: true,
            last_item_count: Some(0),
            watcher: None,
            pending_conflicts: Vec::new(),
            rewrite_on_unlock: false,
            dirty_from_corrupt: false,
            snapshot_retry: false,
            key_mismatch: false,
            save_blocked: None,
            locked_fallback: None,
            sibling_reports: HashMap::new(),
            prune_clock_offset: Duration::ZERO,
        };
        if let Err(e) = this.write(&bytes, Mode::NoReplace) {
            // Only our own empty directory; never anything that appeared inside it meanwhile.
            if let Err(rm) = fs::remove_dir(&this.path) {
                tracing::warn!(path = %this.path.display(), error = %rm, "could not remove package after failed create");
            }
            return Err(e);
        }
        this.hooks.pin(&this.file);
        tracing::info!(path = %this.path.display(), "created vault");
        Ok(this)
    }

    /// Read and parse the vault in the package directory `path`; the result is locked.
    /// `device_id` identifies this install and is stamped on the vault at every unlock (core
    /// cannot know it).
    ///
    /// [`SyncError::NoVault`] if `path` or its `vault.bin` does not exist;
    /// [`SyncError::NotAPackage`] if `path` is a regular file (the pre-package single-file
    /// layout, which is not migrated).
    ///
    /// A symlink to a package is resolved: the package's real location becomes [`path`], so
    /// the watcher observes the directory the package actually lives in.
    ///
    /// [`path`]: SyncedVault::path
    pub fn open(
        path: &Path,
        device_id: Uuid,
        hooks: Arc<dyn CloudHooks>,
    ) -> Result<Self, SyncError> {
        let resolved;
        let path = match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                resolved = fs::canonicalize(path).map_err(|e| match e.kind() {
                    ErrorKind::NotFound => SyncError::NoVault(path.to_owned()),
                    _ => SyncError::io(path, e),
                })?;
                resolved.as_path()
            }
            _ => path,
        };
        match fs::metadata(path) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(SyncError::NotAPackage(path.to_owned())),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(SyncError::NoVault(path.to_owned()));
            }
            Err(e) => return Err(SyncError::io(path, e)),
        }
        let file = package::vault_file(path);
        if fs::symlink_metadata(&file).is_ok_and(|m| m.is_dir()) {
            return Err(SyncError::NoVault(file));
        }
        hooks.ensure_downloaded(&file, DOWNLOAD_TIMEOUT)?;
        let bytes = match fs::read(&file) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(SyncError::NoVault(file));
            }
            Err(e) => return Err(SyncError::io(&file, e)),
        };
        let locked = LockedVault::parse(&bytes)?;
        let last_written = Some(fingerprint(&file, &bytes));
        hooks.pin(&file);
        tracing::info!(path = %path.display(), size = bytes.len(), "opened vault");
        Ok(Self {
            path: path.to_owned(),
            file,
            device_id,
            hooks,
            locked,
            unlocked: None,
            dirty: false,
            last_written,
            subscribers: Mutex::default(),
            backup_enabled: true,
            retention_multiplier: backup::RETENTION_MULTIPLIER_DEFAULT,
            first_save_after_unlock: false,
            last_item_count: None,
            watcher: None,
            pending_conflicts: Vec::new(),
            rewrite_on_unlock: false,
            dirty_from_corrupt: false,
            snapshot_retry: false,
            key_mismatch: false,
            save_blocked: None,
            locked_fallback: None,
            sibling_reports: HashMap::new(),
            prune_clock_offset: Duration::ZERO,
        })
    }

    /// Unlock with the master password.
    ///
    /// The primary is re-read first if it differs from the copy we hold (the on-disk copy is
    /// authoritative, 03 §3 step 5), whether or not a watcher is running. If that new version
    /// fails its integrity check, the previously verified version is opened instead,
    /// [`SyncEvent::CorruptOnDisk`] is emitted and the vault is marked dirty so the next save
    /// rewrites the file. Conflicted copies queued while locked are absorbed before this
    /// returns (03 §6 step 2).
    ///
    /// If already unlocked, the password is verified against the on-disk vault and the
    /// in-memory vault (with unsaved edits) is kept, except after [`SyncEvent::KeyMismatch`]:
    /// then the on-disk vault opened with this password becomes the in-memory vault, with the
    /// previous in-memory items merged into it ([`SyncEvent::KeyRotatedOnDisk`], then
    /// [`SyncEvent::Merged`]), and saving is allowed again. If the on-disk vault instead fails
    /// its integrity check (a tampered first record looks like a key mismatch to the cached
    /// key), the in-memory vault wins: [`SyncEvent::CorruptOnDisk`], dirty, rewritten on the
    /// next save.
    ///
    /// Limitation: a rollback of the file to a version from before a key rotation opens with
    /// the same password and is adopted like a rotation. That is undetectable by design (no
    /// rollback protection in the format); the event lets the app tell the user.
    pub fn unlock(&mut self, password: &SecretString) -> Result<(), SyncError> {
        self.open_with(true, |locked| locked.unlock(password))
    }

    /// Unlock through the key slot `slot` with a caller-held KEK (Touch ID path). Same
    /// behaviour as [`SyncedVault::unlock`], except that it cannot resolve a
    /// [`SyncEvent::KeyMismatch`]: that needs the password, and this returns
    /// [`SyncError::KeyMismatch`].
    pub fn unlock_with_kek(&mut self, slot: Uuid, kek: &SecretVec<u8>) -> Result<(), SyncError> {
        self.open_with(false, |locked| locked.unlock_with_kek(slot, kek))
    }

    fn open_with(
        &mut self,
        password_path: bool,
        open: impl Fn(&LockedVault) -> Result<UnlockedVault, VaultError>,
    ) -> Result<(), SyncError> {
        if self.unlocked.is_some() {
            if !self.key_mismatch {
                open(&self.locked)?;
                return Ok(());
            }
            if !password_path {
                return Err(SyncError::KeyMismatch);
            }
            match open(&self.locked) {
                Ok(theirs) => self.adopt_reverified(theirs),
                Err(VaultError::Tampered(kind)) => {
                    tracing::warn!(
                        ?kind,
                        "on-disk vault is tampered, not re-keyed; keeping ours"
                    );
                    self.key_mismatch = false;
                    if let Some(prev) = self.locked_fallback.take() {
                        self.locked = prev;
                    }
                    self.mark_corrupt();
                }
                Err(e) => return Err(e.into()),
            }
            return Ok(());
        }
        let disk_read = self.refresh_locked_from_disk();
        let vault = match open(&self.locked) {
            Ok(v) => v,
            Err(VaultError::Tampered(kind)) => {
                let Some(prev) = self.locked_fallback.take() else {
                    return Err(VaultError::Tampered(kind).into());
                };
                let v = match open(&prev) {
                    Ok(v) => v,
                    Err(_) => {
                        self.locked_fallback = Some(prev);
                        return Err(VaultError::Tampered(kind).into());
                    }
                };
                tracing::warn!(
                    ?kind,
                    "on-disk vault is tampered; opened the last verified version"
                );
                self.locked = prev;
                self.rewrite_on_unlock = true;
                self.emit(SyncEvent::CorruptOnDisk);
                v
            }
            Err(e) => return Err(e.into()),
        };
        self.locked_fallback = None;
        self.install(vault);
        self.after_unlock();
        // Orphan cleanup once per unlock, only when memory provably matches what is on disk:
        // the primary was read, nothing is pending a write, saving is allowed.
        if disk_read && !self.dirty && !self.key_mismatch && self.save_blocked.is_none() {
            self.prune_orphan_attachments();
        }
        Ok(())
    }

    fn install(&mut self, mut vault: UnlockedVault) {
        vault.set_device_id(self.device_id);
        self.last_item_count = Some(vault.items().count());
        self.first_save_after_unlock = true;
        self.unlocked = Some(vault);
        self.dirty = false;
        self.dirty_from_corrupt = false;
        self.key_mismatch = false;
    }

    /// Drop the unlocked vault (zeroizing its keys and items) and discard unsaved edits. The
    /// app is expected to `save` first (03 §8 "Autosave").
    ///
    /// When saving is impossible (a [`SyncEvent::KeyMismatch`] stands, or
    /// [`SyncError::SaveBlocked`] applies, dirty or not: our last saved state is then no longer
    /// on disk either), the in-memory vault is first written,
    /// encrypted, to the backups directory as `<name>-<timestamp>-unsaved.vault.bin`
    /// ([`BackupKind::Unsaved`], [`SyncEvent::BackupTaken`]) so nothing is lost. It opens with
    /// the password that unlocked this session.
    pub fn lock(&mut self) {
        if let Some(vault) = &self.unlocked
            && (self.key_mismatch || self.save_blocked.is_some())
            && !self.newest_unsaved_covers(vault)
        {
            let bytes = vault.serialize();
            if let Err(e) = self.snapshot(&bytes, SystemTime::now(), BackupKind::Unsaved) {
                tracing::error!(error = %e, "could not preserve unsaved vault before locking");
                self.emit(SyncEvent::Error(format!(
                    "unsaved changes could not be preserved: {e}"
                )));
            }
        }
        // A corrupt primary seen while unlocked was scheduled for rewrite only through `dirty`,
        // which locking discards; carry it over so the next unlock still rewrites the file.
        if std::mem::take(&mut self.dirty_from_corrupt) {
            self.rewrite_on_unlock = true;
        }
        self.unlocked = None;
        self.dirty = false;
        self.key_mismatch = false;
    }

    /// Whether the newest [`BackupKind::Unsaved`] file already holds everything in `vault`
    /// (same key and slots, and merging `vault` into it changes nothing), so locking again
    /// need not write another. Byte comparison cannot work: every `serialize` uses fresh
    /// nonces. Any failure to read or open it counts as "not covered", and so does an evicted
    /// (cloud-only) file: `lock` must not block on a download, so it writes a new one.
    fn newest_unsaved_covers(&self, vault: &UnlockedVault) -> bool {
        let Ok(list) = backup::list_backups(&self.path) else {
            return false;
        };
        let Some(newest) = list.iter().find(|b| b.kind == BackupKind::Unsaved) else {
            return false;
        };
        if self.hooks.is_evicted(&newest.path) {
            return false;
        }
        let Ok(Some(ReadParsed {
            parsed: Ok(locked), ..
        })) = self.read_parsed(&newest.path)
        else {
            return false;
        };
        let Ok(mut copy) = locked.unlock_with_key(&vault.export_vault_key(), self.device_id) else {
            return false;
        };
        copy.slots().eq(vault.slots()) && copy.merge_from(vault).is_ok_and(|r| !r.changed())
    }

    pub fn vault(&self) -> Option<&UnlockedVault> {
        self.unlocked.as_ref()
    }

    /// Mutate the unlocked vault and mark it dirty.
    pub fn edit<R>(&mut self, f: impl FnOnce(&mut UnlockedVault) -> R) -> Result<R, SyncError> {
        let vault = self.unlocked.as_mut().ok_or(SyncError::Locked)?;
        let r = f(vault);
        self.dirty = true;
        Ok(r)
    }

    /// Atomically write the unlocked vault to disk (03 §2). A clean vault is not rewritten.
    ///
    /// Before writing, the primary is compared with what we last wrote or read; a version that
    /// landed since (with or without a watcher) is reconciled first (03 §3), so a peer's write
    /// is merged rather than overwritten. Refuses with [`SyncError::KeyMismatch`] or
    /// [`SyncError::SaveBlocked`] while either applies, even when clean.
    pub fn save(&mut self) -> Result<(), SyncError> {
        if self.unlocked.is_none() {
            return Err(SyncError::Locked);
        }
        // A primary we cannot read (cloud timeout, I/O) may hold a peer's unmerged version:
        // fail rather than overwrite it.
        if self.dirty {
            self.reconcile_primary()?;
        }
        if self.key_mismatch {
            return Err(SyncError::KeyMismatch);
        }
        if let Some(blocked) = self.save_blocked {
            return Err(SyncError::SaveBlocked(blocked));
        }
        if !self.dirty {
            return Ok(());
        }
        let vault = self.unlocked.as_ref().ok_or(SyncError::Locked)?;
        // Step 1. Re-parse first: it is cheap, keeps `locked` current for the next unlock, and
        // guarantees we never put bytes on disk that we could not read back.
        let bytes = vault.serialize();
        let item_count = vault.items().count();
        let locked = LockedVault::parse(&bytes)?;
        self.write(&bytes, Mode::Replace)?;
        self.locked = locked;
        self.locked_fallback = None;
        self.dirty = false;
        self.dirty_from_corrupt = false;
        let first = std::mem::take(&mut self.first_save_after_unlock);
        self.maybe_backup(&bytes, item_count, first);
        self.prune_orphan_attachments();
        Ok(())
    }

    /// Steps 2-6 of 03 §2. `create` uses [`Mode::NoReplace`] so a file that appeared after its
    /// existence check is never clobbered; `save` uses [`Mode::Replace`].
    fn write(&mut self, bytes: &[u8], mode: Mode) -> Result<(), SyncError> {
        write_atomic(&self.file, bytes, mode)?;
        self.last_written = Some(fingerprint(&self.file, bytes));
        tracing::debug!(path = %self.file.display(), size = bytes.len(), "saved vault");
        Ok(())
    }

    /// 03 §2 step 7 / §4: snapshot `bytes` (just written) if the newest snapshot is an hour
    /// old, the item count dropped since the last save, or this is the first save after
    /// unlock. The save has already succeeded, so a failure here is logged and emitted as
    /// [`SyncEvent::Error`], never returned.
    fn maybe_backup(&mut self, bytes: &[u8], item_count: usize, first_save_after_unlock: bool) {
        // A trigger whose snapshot failed last time (any of the three) fires again now.
        let decreased = self.last_item_count.is_some_and(|prev| item_count < prev)
            | std::mem::take(&mut self.snapshot_retry);
        self.last_item_count = Some(item_count);
        if !self.backup_enabled {
            return;
        }
        let now = SystemTime::now();
        let newest = match backup::list_backups(&self.path) {
            // Only our own snapshots count (a conflict or unsaved copy is not a backup of the
            // disk), and only past ones: a future-dated file from a skewed clock must not
            // shadow the real newest.
            Ok(list) => list
                .iter()
                .find(|b| b.kind == BackupKind::Snapshot && b.taken_at <= now)
                .map(|b| b.taken_at),
            Err(e) => {
                tracing::warn!(error = %e, "could not list backups; taking one");
                None
            }
        };
        if !backup::should_snapshot(newest, now, decreased, first_save_after_unlock) {
            return;
        }
        if let Err(e) = self.snapshot(bytes, now, BackupKind::Snapshot) {
            // Retry on the next save rather than losing the triggered snapshot.
            self.snapshot_retry = true;
            tracing::warn!(error = %e, "backup after save failed");
            self.emit(SyncEvent::Error(format!("backup failed: {e}")));
        }
    }

    /// Write a snapshot, announce it, then run retention (whose failures are only logged).
    fn snapshot(
        &self,
        bytes: &[u8],
        now: SystemTime,
        kind: BackupKind,
    ) -> Result<PathBuf, SyncError> {
        let path = backup::write_snapshot(&self.path, bytes, now, kind)?;
        self.emit(SyncEvent::BackupTaken(path.clone()));
        if let Err(e) = backup::apply_retention(&self.path, now, self.retention_multiplier, &path) {
            tracing::warn!(error = %e, "backup retention failed");
        }
        Ok(path)
    }

    /// Snapshots, unsaved copies and absorbed conflict packages in `<name>.vault/backups/`,
    /// newest first.
    pub fn backups(&self) -> Result<Vec<BackupInfo>, SyncError> {
        backup::list_backups(&self.path)
    }

    /// Snapshot `vault.bin` as it is on disk now, regardless of policy or the enabled
    /// setting ("Back up now"). Works while locked. Unsaved edits are not included; the
    /// bytes must parse as a vault so every snapshot stays independently openable.
    pub fn backup_now(&mut self) -> Result<PathBuf, SyncError> {
        let read = self
            .read_parsed(&self.file)?
            .ok_or_else(|| not_found(&self.file))?;
        read.parsed?;
        self.snapshot(&read.bytes, SystemTime::now(), BackupKind::Snapshot)
    }

    /// Replace the vault with the backup at `backup` (03 §4 "Restore"): a `.vault.bin`
    /// snapshot file, or a package directory (an absorbed `conflict-…` package), whose
    /// `vault.bin` is used.
    ///
    /// `password` must unlock the backup (it may differ from the current password if that has
    /// since changed); the backup must be of this vault (same `vault_id`). The current primary
    /// is snapshotted first. If it does not parse, its raw bytes are kept as a
    /// [`BackupKind::Unsaved`] file (never pruned) before being replaced; if it is missing,
    /// nothing is kept. If it was written by a newer format version, the restore is refused
    /// with [`SaveBlocked::NewerVersion`]: replacing it would destroy that device's data, so
    /// the user must update the app first. Conflicted copies queued while locked are absorbed
    /// before this returns, as after `unlock`. Then the backup's exact
    /// bytes atomically replace the primary and the in-memory vault becomes the restored one,
    /// unlocked and clean. Unsaved edits are discarded. On any error before the replace,
    /// nothing changes.
    ///
    /// The pre-restore snapshot runs retention, which may prune the very backup being restored
    /// from. That is harmless: its bytes are already in memory and written to the primary, and
    /// the next save snapshots again (it counts as the first save after unlock).
    pub fn restore_from(
        &mut self,
        backup: &Path,
        password: &SecretString,
    ) -> Result<(), SyncError> {
        let source = if backup.is_dir() {
            package::vault_file(backup)
        } else {
            backup.to_owned()
        };
        let ReadParsed { bytes, parsed } = self
            .read_parsed(&source)?
            .ok_or_else(|| not_found(&source))?;
        let locked = parsed?;
        let (expected, found) = (self.locked.vault_id(), locked.vault_id());
        if found != expected {
            return Err(SyncError::ForeignVault { expected, found });
        }
        let mut vault = locked.unlock(password)?;
        vault.set_device_id(self.device_id);

        match self.read_parsed(&self.file)? {
            Some(ReadParsed {
                bytes: current,
                parsed: Ok(_),
            }) => {
                self.snapshot(&current, SystemTime::now(), BackupKind::Snapshot)?;
            }
            Some(ReadParsed {
                parsed: Err(VaultError::UnsupportedVersion(v)),
                ..
            }) => {
                // A newer build wrote it; replacing it would destroy that device's data.
                return Err(SyncError::SaveBlocked(SaveBlocked::NewerVersion(v)));
            }
            Some(ReadParsed {
                bytes: current,
                parsed: Err(e),
            }) => {
                // Not openable, but maybe recoverable by hand: keep the raw bytes, unpruned.
                tracing::warn!(path = %self.path.display(), error = %e, "primary is unparseable; keeping a raw copy before restoring");
                self.snapshot(&current, SystemTime::now(), BackupKind::Unsaved)?;
            }
            None => {
                tracing::warn!(path = %self.path.display(), "primary is missing; restoring without a pre-restore snapshot");
            }
        }

        self.write(&bytes, Mode::Replace)?;
        self.locked = locked;
        self.locked_fallback = None;
        // An explicit restore replaces whatever is on disk (a newer-format file was refused
        // above), so earlier blocks and pending rewrites no longer apply.
        self.save_blocked = None;
        self.rewrite_on_unlock = false;
        self.install(vault);
        // Restoring from locked is an unlock: absorb conflicted copies queued meanwhile.
        self.after_unlock();
        tracing::info!(path = %self.path.display(), from = %backup.display(), "restored vault from backup");
        Ok(())
    }

    /// 03 §4 "enable/disable". Disabling stops automatic snapshots on save; `backup_now` and
    /// the pre-restore snapshot still happen.
    pub fn set_backup_enabled(&mut self, enabled: bool) {
        self.backup_enabled = enabled;
    }

    pub fn backup_enabled(&self) -> bool {
        self.backup_enabled
    }

    /// 03 §4 retention multiplier, clamped to 0.5-4.0 (NaN resets to 1.0).
    pub fn set_retention_multiplier(&mut self, multiplier: f32) {
        self.retention_multiplier = backup::clamp_multiplier(multiplier);
    }

    pub fn retention_multiplier(&self) -> f32 {
        self.retention_multiplier
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// A new receiver for [`SyncEvent`]s. Every subscriber gets every event.
    pub fn subscribe(&self) -> Receiver<SyncEvent> {
        let (tx, rx) = crossbeam_channel::unbounded();
        self.subscribers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(tx);
        rx
    }

    /// Broadcast to every live subscriber, dropping the ones whose receiver is gone.
    pub(crate) fn emit(&self, event: SyncEvent) {
        self.subscribers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|tx| tx.send(event.clone()).is_ok());
    }

    /// The package directory (`<name>.vault/`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The vault file inside the package (`<name>.vault/vault.bin`).
    pub fn vault_file(&self) -> &Path {
        &self.file
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// Header facts of the on-disk vault, available while locked.
    pub fn locked_summary(&self) -> LockedSummary {
        LockedSummary {
            vault_id: self.locked.vault_id(),
            slots: self.locked.slots().collect(),
        }
    }

    /// Fingerprint of the last bytes this instance wrote to or read from `vault.bin`. Exposed
    /// for tests.
    #[doc(hidden)]
    pub fn last_written(&self) -> Option<LastWritten> {
        self.last_written
    }
}

/// A file read through the cloud hooks, with its parse result.
pub(crate) struct ReadParsed {
    pub(crate) bytes: Vec<u8>,
    pub(crate) parsed: Result<LockedVault, VaultError>,
}

impl SyncedVault {
    /// `ensure_downloaded` → read → parse (03 §7: download before every read of the primary
    /// or a conflicted copy). `Ok(None)` when the file does not exist.
    pub(crate) fn read_parsed(&self, path: &Path) -> Result<Option<ReadParsed>, SyncError> {
        self.hooks.ensure_downloaded(path, DOWNLOAD_TIMEOUT)?;
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(SyncError::io(path, e)),
        };
        let parsed = LockedVault::parse(&bytes);
        Ok(Some(ReadParsed { bytes, parsed }))
    }
}

fn not_found(path: &Path) -> SyncError {
    SyncError::io(path, ErrorKind::NotFound.into())
}

/// Size and hash come from the bytes themselves; a failed stat only loses the mtime pre-check,
/// never the write that already succeeded.
fn fingerprint(path: &Path, bytes: &[u8]) -> LastWritten {
    let mtime = match fs::metadata(path).and_then(|m| m.modified()) {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not stat vault; echo check will use the hash");
            None
        }
    };
    LastWritten {
        mtime,
        size: bytes.len() as u64,
        hash: *blake3::hash(bytes).as_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::NoopHooks;

    #[test]
    fn emit_reaches_every_live_subscriber() {
        let dir = tempfile::tempdir().unwrap();
        let pw = SecretString::new("pw".to_owned());
        let v = SyncedVault::create(
            &dir.path().join("a.vault"),
            &pw,
            KdfParams::for_tests(),
            Uuid::from_u128(1),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let a = v.subscribe();
        let b = v.subscribe();
        drop(v.subscribe());
        v.emit(SyncEvent::CorruptOnDisk);
        assert_eq!(a.try_recv().unwrap(), SyncEvent::CorruptOnDisk);
        assert_eq!(b.try_recv().unwrap(), SyncEvent::CorruptOnDisk);
        assert_eq!(v.subscribers.lock().unwrap().len(), 2);
    }
}
