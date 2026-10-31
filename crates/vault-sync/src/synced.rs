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

use crate::atomic::{Mode, write_atomic_stat};
use crate::attachments::prune_stale_vault_tmp;
use crate::backup::{self, BackupInfo, BackupKind};
use crate::cloud::CloudHooks;
use crate::error::{SaveBlocked, SyncError};
use crate::event::SyncEvent;
use crate::lock::PackageLock;
use crate::package;
use crate::watch::Watcher;

/// How long `open` waits for the cloud provider to materialise the file (03 §7).
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest vault file (`vault.bin`, a backup or a conflicted copy) that is read (03 §2):
/// 64 MiB. Larger files are refused with [`SyncError::PrimaryTooLarge`] before parsing, so a
/// planted or corrupt file cannot make us allocate without bound.
pub const MAX_VAULT_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// What [`SyncedVault::lock`] did with the in-memory vault before dropping it (03 §8).
#[derive(Debug)]
pub enum LockOutcome {
    /// Nothing needed preserving: the vault was already locked, or clean with its state on
    /// disk.
    Clean,
    /// Unsaved state is in this [`BackupKind::Unsaved`] file (written now, or an existing one
    /// that already held all of it). It opens with the password of the locked session. If
    /// only the directory fsync after writing it failed, this is still returned (the bytes
    /// are on disk) but the file is snapshotted, not confirmed durable; a
    /// [`SyncEvent::Error`] says so.
    Snapshotted(PathBuf),
    /// Unsaved state could NOT be preserved (the Unsaved backup failed with this error) and
    /// is gone: the vault is locked regardless. [`SyncEvent::Error`] was emitted too. The app
    /// must not tell the user their changes were kept.
    Unpreserved(SyncError),
}

/// Fingerprint of the bytes most recently written to (or read from) the primary file, used to
/// recognise our own writes echoing back through the watcher (03 §2 step 6, §3 steps 1-2).
///
/// `hash` (blake3 of the exact bytes) is the authoritative comparison key. `(mtime, ctime,
/// inode, size)` is only a fast pre-check (03 §2 step 6): mtime and size alone miss a
/// same-size write within one timestamp tick on coarse filesystems (V-05), while every atomic
/// replace gets a new inode and the local kernel sets ctime on it. The stat fields are `None`
/// when the file could not be stat'ed after writing; the echo check then goes straight to the
/// hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastWritten {
    pub mtime: Option<SystemTime>,
    pub ctime: Option<SystemTime>,
    pub inode: Option<u64>,
    pub size: u64,
    pub hash: [u8; 32],
}

impl LastWritten {
    /// The step-1 pre-check: `meta` describes the very file this fingerprint was taken from.
    /// Never true when the fingerprint has no stat.
    pub(crate) fn stat_matches(&self, meta: &fs::Metadata) -> bool {
        let (mtime, ctime, inode) = stat_of(meta);
        self.mtime.is_some()
            && self.size == meta.len()
            && self.mtime == mtime
            && self.ctime == ctime
            && self.inode == inode
    }
}

/// `(mtime, ctime, inode)` of `meta`.
fn stat_of(meta: &fs::Metadata) -> (Option<SystemTime>, Option<SystemTime>, Option<u64>) {
    use std::os::unix::fs::MetadataExt;
    let ctime = u64::try_from(meta.ctime()).ok().and_then(|secs| {
        let nanos = u32::try_from(meta.ctime_nsec()).ok()?;
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
    });
    (meta.modified().ok(), ctime, Some(meta.ino()))
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
    /// The primary was found missing while unlocked ([`SyncEvent::PrimaryMissing`] emitted,
    /// vault marked dirty). Cleared when the primary is read or written again, and on lock.
    primary_missing: bool,
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
    /// directory must exist. The returned vault is unlocked and clean. The header and the
    /// password slot record the current time as `created_at` (unix seconds, 01 §2).
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
        let created_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let vault = UnlockedVault::create_with_created_at(password, kdf, device_id, created_at);
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
            primary_missing: false,
            prune_clock_offset: Duration::ZERO,
        };
        let written = match this.write(&bytes, Mode::NoReplace) {
            Ok(durable) => durable.map_err(|e| (e, true)),
            Err(e) => Err((e, false)),
        };
        if let Err((e, ours_on_disk)) = written {
            // Our own file (written, but its directory entry not known durable) and our own
            // directory; never anything else that appeared inside it meanwhile.
            if ours_on_disk && let Err(rm) = fs::remove_file(&this.file) {
                tracing::warn!(path = %this.file.display(), error = %rm, "could not remove vault file after failed create");
            }
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
        // Shared lock around the read and the stat (03 §2): never between a writer's read and
        // its rename. Cheap belt-and-braces, as rename is atomic anyway.
        let read_lock = PackageLock::shared(path)?;
        let (bytes, meta) = match read_with_stat(&file) {
            Ok(r) => r,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(SyncError::NoVault(file));
            }
            Err(e) => return Err(read_error(&file, e)),
        };
        drop(read_lock);
        let last_written = Some(fingerprint(Some(&meta), &bytes));
        let locked = LockedVault::parse(&bytes)?;
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
            primary_missing: false,
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
    /// in-memory vault (with unsaved edits) is kept, except after [`SyncEvent::KeyMismatch`] or
    /// [`SyncEvent::KeyRotatedOnDisk`]: then the on-disk vault opened with this password
    /// becomes the in-memory vault, with the previous in-memory items merged into it
    /// ([`SyncEvent::Merged`]), and saving is allowed again. If the on-disk vault instead fails
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
        // Stale tmp cleanup runs only while unlocked (03 §1.1 "never while locked").
        self.prune_stale_tmp(SystemTime::now() + self.prune_clock_offset);
        self.after_unlock();
        // Unlocked over a primary that is gone: what we just opened is the only copy.
        if !disk_read
            && matches!(fs::symlink_metadata(&self.file), Err(e) if e.kind() == ErrorKind::NotFound)
        {
            self.note_primary_missing();
        }
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

    /// Drop the unlocked vault (zeroizing its keys and items). The app is expected to `save`
    /// first (03 §8 "Autosave"); `lock` itself never writes the primary.
    ///
    /// Unsaved edits are preserved when possible (03 §8): when the vault is dirty (a save
    /// failed or was not attempted), the primary is missing (checked here too, so this holds
    /// without a watcher), or saving is
    /// impossible (a [`SyncEvent::KeyMismatch`] stands, or [`SyncError::SaveBlocked`] applies,
    /// dirty or not: our last saved state is then no longer on disk either), the in-memory
    /// vault is first written, encrypted, to the backups directory as
    /// `<name>-<timestamp>-unsaved.vault.bin` ([`BackupKind::Unsaved`], never pruned;
    /// [`SyncEvent::BackupTaken`]), unless the newest Unsaved file already holds all of it. It
    /// opens with the password that unlocked this session. A clean vault that can be saved
    /// (the usual save-then-lock) writes nothing.
    ///
    /// Always locks. The returned [`LockOutcome`] says whether anything needed preserving and
    /// whether that worked; on [`LockOutcome::Unpreserved`] the unsaved state is lost.
    #[must_use = "the app must not claim unsaved changes were kept on LockOutcome::Unpreserved"]
    pub fn lock(&mut self) -> LockOutcome {
        // Without a watcher nothing may have noticed a deleted primary yet; a stat is cheap.
        if self.unlocked.is_some()
            && !self.primary_missing
            && matches!(fs::symlink_metadata(&self.file), Err(e) if e.kind() == ErrorKind::NotFound)
        {
            self.note_primary_missing();
        }
        let outcome = match &self.unlocked {
            Some(vault)
                if self.dirty
                    || self.key_mismatch
                    || self.save_blocked.is_some()
                    || self.primary_missing =>
            {
                match self.newest_unsaved_covering(vault) {
                    Some(path) => LockOutcome::Snapshotted(path),
                    None => {
                        let bytes = vault.serialize();
                        match self.snapshot_unconfirmed(
                            &bytes,
                            SystemTime::now(),
                            BackupKind::Unsaved,
                        ) {
                            Ok((path, Ok(()))) => LockOutcome::Snapshotted(path),
                            Ok((path, Err(e))) => {
                                tracing::warn!(path = %path.display(), error = %e, "unsaved backup written but not confirmed durable");
                                self.emit(SyncEvent::Error(format!(
                                    "unsaved changes were written to {} but may not be durable: {e}",
                                    path.display()
                                )));
                                LockOutcome::Snapshotted(path)
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "could not preserve unsaved vault before locking");
                                self.emit(SyncEvent::Error(format!(
                                    "unsaved changes could not be preserved: {e}"
                                )));
                                LockOutcome::Unpreserved(e)
                            }
                        }
                    }
                }
            }
            _ => LockOutcome::Clean,
        };
        // A corrupt primary seen while unlocked was scheduled for rewrite only through `dirty`,
        // which locking discards; carry it over so the next unlock still rewrites the file.
        if std::mem::take(&mut self.dirty_from_corrupt) {
            self.rewrite_on_unlock = true;
        }
        self.unlocked = None;
        self.dirty = false;
        self.key_mismatch = false;
        self.primary_missing = false;
        outcome
    }

    /// The newest [`BackupKind::Unsaved`] file if it already holds everything in `vault`
    /// (same key and slots, and merging `vault` into it changes nothing), so locking again
    /// need not write another. Byte comparison cannot work: every `serialize` uses fresh
    /// nonces. Any failure to read or open it counts as "not covered", and so does an evicted
    /// (cloud-only) file: `lock` must not block on a download, so it writes a new one.
    fn newest_unsaved_covering(&self, vault: &UnlockedVault) -> Option<PathBuf> {
        let list = backup::list_backups(&self.path).ok()?;
        let newest = list.into_iter().find(|b| b.kind == BackupKind::Unsaved)?;
        if self.hooks.is_evicted(&newest.path) {
            return None;
        }
        let Ok(Some(ReadParsed {
            parsed: Ok(locked), ..
        })) = self.read_parsed(&newest.path)
        else {
            return None;
        };
        let mut copy = locked
            .unlock_with_key(&vault.export_vault_key(), self.device_id)
            .ok()?;
        (copy.slots().eq(vault.slots()) && copy.merge_from(vault).is_ok_and(|r| !r.changed()))
            .then_some(newest.path)
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
    /// [`SyncError::SaveBlocked`] while either applies, even when clean; a refused save emits
    /// [`SyncEvent::SaveBlocked`] (once: if this save's own pre-write read just found the
    /// blocking file, that report is the one).
    ///
    /// A dirty save holds the package's exclusive advisory lock (`<name>.vault/.lock`, 03 §2)
    /// from the pre-write read through the rename, the backup and the cleanup, so another
    /// process saving the same vault cannot interleave its read-modify-write with ours (V-02).
    /// [`SyncError::SaveLockTimeout`] if the lock is not free within 10 s; nothing is written then.
    pub fn save(&mut self) -> Result<(), SyncError> {
        if self.unlocked.is_none() {
            return Err(SyncError::Locked);
        }
        // Download an evicted primary BEFORE taking the lock: `ensure_downloaded` may block for
        // up to 30 s, longer than another process waits for the lock. Inside, the re-check in
        // `reconcile_primary` is then a no-op unless the file was evicted again meanwhile.
        let _lock = if self.dirty {
            self.ensure_primary_downloaded()?;
            Some(PackageLock::exclusive(&self.path)?)
        } else {
            None
        };
        // A primary we cannot read (cloud timeout, I/O) may hold a peer's unmerged version:
        // fail rather than overwrite it.
        let blocked_before = self.save_blocked;
        if self.dirty {
            self.reconcile_primary()?;
        }
        if self.key_mismatch {
            return Err(SyncError::KeyMismatch);
        }
        if let Some(blocked) = self.save_blocked {
            // `vet_primary` reports a block when it first sees it; do not repeat that here.
            if blocked_before == Some(blocked) {
                self.emit(SyncEvent::SaveBlocked(blocked));
            }
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
        // A primary that went missing is recreated without replacing: if a peer's file lands
        // meanwhile, `AlreadyExists` leaves us dirty and the next save merges it instead.
        let mode = if self.primary_missing {
            Mode::NoReplace
        } else {
            Mode::Replace
        };
        run_before_primary_write();
        let durable = self.write(&bytes, mode)?;
        // The file on disk is now ours either way.
        self.locked = locked;
        self.locked_fallback = None;
        // The rename happened but the directory fsync failed (03 §2 step 5): not known
        // durable, so stay dirty and let the next save write (and fsync) again.
        durable?;
        self.dirty = false;
        self.dirty_from_corrupt = false;
        let first = std::mem::take(&mut self.first_save_after_unlock);
        self.maybe_backup(&bytes, item_count, first);
        self.prune_orphan_attachments();
        self.prune_stale_tmp(SystemTime::now() + self.prune_clock_offset);
        Ok(())
    }

    /// Delete `.vault.bin.tmp-*` files in the package older than 1 h (03 §1.1, same rule as
    /// attachment tmp files): left by a crash between tmp creation and rename. Failures are
    /// logged only.
    fn prune_stale_tmp(&self, now: SystemTime) {
        match prune_stale_vault_tmp(&self.path, now) {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, "removed stale vault tmp files"),
            Err(e) => tracing::warn!(error = %e, "stale tmp cleanup failed"),
        }
    }

    /// Steps 2-6 of 03 §2. `create` uses [`Mode::NoReplace`] so a file that appeared after its
    /// existence check is never clobbered; `save` uses [`Mode::Replace`] (`NoReplace` while the
    /// primary is missing).
    ///
    /// Outer `Err`: nothing was written. Inner `Err`: `bytes` ARE the primary now (recorded as
    /// such), but the directory fsync failed, so the write is not known durable; the caller
    /// must keep a retry pending.
    fn write(&mut self, bytes: &[u8], mode: Mode) -> Result<Result<(), SyncError>, SyncError> {
        let written = write_atomic_stat(&self.file, bytes, mode)?;
        self.last_written = Some(fingerprint_after_write(
            &self.file,
            written.tmp_stat.as_ref(),
            bytes,
        ));
        self.primary_missing = false;
        tracing::debug!(path = %self.file.display(), size = bytes.len(), "saved vault");
        Ok(written.dir_sync)
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
    /// A directory fsync failure after the write is an error here (see
    /// [`SyncedVault::snapshot_unconfirmed`]).
    fn snapshot(
        &self,
        bytes: &[u8],
        now: SystemTime,
        kind: BackupKind,
    ) -> Result<PathBuf, SyncError> {
        let (path, durable) = self.snapshot_unconfirmed(bytes, now, kind)?;
        durable?;
        Ok(path)
    }

    /// [`SyncedVault::snapshot`], reporting the directory fsync separately: an inner `Err`
    /// means the snapshot file exists (and was announced) but is not confirmed durable.
    fn snapshot_unconfirmed(
        &self,
        bytes: &[u8],
        now: SystemTime,
        kind: BackupKind,
    ) -> Result<(PathBuf, Result<(), SyncError>), SyncError> {
        let (path, durable) = backup::write_snapshot(&self.path, bytes, now, kind)?;
        self.emit(SyncEvent::BackupTaken(path.clone()));
        if let Err(e) = backup::apply_retention(&self.path, now, self.retention_multiplier, &path) {
            tracing::warn!(error = %e, "backup retention failed");
        }
        Ok((path, durable))
    }

    /// Snapshots, unsaved copies and absorbed conflict packages in `<name>.vault/backups/`,
    /// newest first.
    pub fn backups(&self) -> Result<Vec<BackupInfo>, SyncError> {
        backup::list_backups(&self.path)
    }

    /// Delete one backup (user-initiated, 03 §8): a snapshot or unsaved file, or an absorbed
    /// conflict package directory (removed recursively; symlinks inside are removed, not
    /// followed). Any [`BackupKind`] may be deleted, including `Unsaved` and `Conflict`, which
    /// retention never prunes. Works while locked.
    ///
    /// `backup`'s parent directory is resolved through symlinks and must be
    /// `<name>.vault/backups/`; the entry itself must be one of [`backups`] and must not be a
    /// symlink (never followed, so it cannot redirect the delete to another file). Anything
    /// else (the primary, the package, a file outside `backups/`, any symlink, an unrecognised
    /// name, a missing path) is refused with [`SyncError::NotABackup`] and nothing is
    /// deleted. If the entry vanishes between that check and the removal (retention in another
    /// process), the delete still succeeds. Emits
    /// [`SyncEvent::BackupDeleted`] with the path as [`backups`] lists it.
    ///
    /// [`backups`]: SyncedVault::backups
    pub fn delete_backup(&mut self, backup: &Path) -> Result<(), SyncError> {
        self.delete_backup_hooked(backup, || {})
    }

    /// [`SyncedVault::delete_backup`] with `between` run after the checks and before the
    /// removal (tests delete the entry there, as another process's retention could).
    fn delete_backup_hooked(
        &mut self,
        backup: &Path,
        between: impl FnOnce(),
    ) -> Result<(), SyncError> {
        let refuse = || SyncError::NotABackup(backup.to_owned());
        // Resolve only the directory: the entry itself is never followed, so a symlink named
        // like a backup cannot redirect the delete to another file (another backup included).
        let name = backup.file_name().ok_or_else(refuse)?;
        let parent = match backup.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let canonical_parent = fs::canonicalize(parent).map_err(|e| match e.kind() {
            ErrorKind::NotFound => refuse(),
            _ => SyncError::io(parent, e),
        })?;
        let backups_dir = package::backups_dir(&self.path);
        let canonical_dir = match fs::canonicalize(&backups_dir) {
            Ok(d) => d,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(refuse()),
            Err(e) => return Err(SyncError::io(&backups_dir, e)),
        };
        if canonical_parent != canonical_dir {
            return Err(refuse());
        }
        let target = canonical_dir.join(name);
        let meta = match fs::symlink_metadata(&target) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(refuse()),
            Err(e) => return Err(SyncError::io(&target, e)),
        };
        if meta.file_type().is_symlink() {
            return Err(refuse());
        }
        let info = backup::list_backups(&self.path)?
            .into_iter()
            .find(|b| b.path.file_name() == Some(name))
            .ok_or_else(refuse)?;
        between();
        let removed = if meta.is_dir() {
            fs::remove_dir_all(&target)
        } else {
            fs::remove_file(&target)
        };
        match removed {
            Ok(()) => {}
            // Already gone (retention or the user in another process): the outcome asked for.
            Err(e) if e.kind() == ErrorKind::NotFound => {
                tracing::debug!(path = %target.display(), "backup vanished before deletion");
            }
            Err(e) => return Err(SyncError::io(&target, e)),
        }
        tracing::info!(path = %info.path.display(), kind = ?info.kind, "deleted backup");
        self.emit(SyncEvent::BackupDeleted(info.path));
        Ok(())
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

        // Like `save`: no other writer between our read of the current primary and the
        // replace. Released before `after_unlock`, whose conflict absorption saves (and locks).
        let write_lock = PackageLock::exclusive(&self.path)?;
        let current = match self.read_parsed(&self.file) {
            // Not a vault this app wrote; too large to keep a copy of. Restoring replaces it.
            Err(SyncError::PrimaryTooLarge(p)) => {
                tracing::warn!(path = %p.display(), "primary is oversized; restoring without a pre-restore copy");
                None
            }
            r => r?,
        };
        match current {
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

        let durable = self.write(&bytes, Mode::Replace)?;
        drop(write_lock);
        self.locked = locked;
        self.locked_fallback = None;
        // An explicit restore replaces whatever is on disk (a newer-format file was refused
        // above), so earlier blocks and pending rewrites no longer apply.
        self.save_blocked = None;
        self.rewrite_on_unlock = false;
        self.install(vault);
        if let Err(e) = durable {
            // The restore took effect but is not known durable: the next save rewrites it.
            self.dirty = true;
            self.emit_error(e);
        }
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

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static BEFORE_PRIMARY_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Tests only: run `f` once on this thread inside the next dirty `save`, after its pre-write
/// read and merge and right before the primary is written (another device's write landing
/// in that window).
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn before_next_primary_write_for_tests(f: impl FnOnce() + 'static) {
    BEFORE_PRIMARY_WRITE.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// Tests only: make the next `n` directory fsyncs on this thread fail with EIO (03 §2 step 5).
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn fail_next_dir_syncs_for_tests(n: u32) {
    crate::atomic::inject_dir_sync_failures(n);
}

#[cfg(any(test, feature = "test-support"))]
fn run_before_primary_write() {
    if let Some(f) = BEFORE_PRIMARY_WRITE.with(|h| h.borrow_mut().take()) {
        f();
    }
}

#[cfg(not(any(test, feature = "test-support")))]
fn run_before_primary_write() {}

/// A file read through the cloud hooks, with its parse result.
pub(crate) struct ReadParsed {
    pub(crate) bytes: Vec<u8>,
    pub(crate) parsed: Result<LockedVault, VaultError>,
}

impl SyncedVault {
    /// `ensure_downloaded` → read → parse (03 §7: download before every read of the primary
    /// or a conflicted copy). `Ok(None)` when the file does not exist;
    /// [`SyncError::PrimaryTooLarge`] beyond [`MAX_VAULT_FILE_SIZE`].
    pub(crate) fn read_parsed(&self, path: &Path) -> Result<Option<ReadParsed>, SyncError> {
        self.hooks.ensure_downloaded(path, DOWNLOAD_TIMEOUT)?;
        let bytes = match read_with_stat(path) {
            Ok((b, _)) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(read_error(path, e)),
        };
        let parsed = LockedVault::parse(&bytes);
        Ok(Some(ReadParsed { bytes, parsed }))
    }
}

fn not_found(path: &Path) -> SyncError {
    SyncError::io(path, ErrorKind::NotFound.into())
}

/// Open `path` once, `fstat` the handle, then read through that same handle, so the stat
/// describes exactly the file whose bytes are returned even if the path is replaced meanwhile
/// (03 §2 step 6). The stat is taken before the read: an in-place write after it changes the
/// file's stat, so the next echo check reads again.
pub(crate) fn read_with_stat(path: &Path) -> std::io::Result<(Vec<u8>, fs::Metadata)> {
    read_with_stat_hooked(path, || {})
}

/// [`read_with_stat`] with `between` run after the open and before the fstat (tests replace
/// the path there).
fn read_with_stat_hooked(
    path: &Path,
    between: impl FnOnce(),
) -> std::io::Result<(Vec<u8>, fs::Metadata)> {
    let mut file = fs::File::open(path)?;
    between();
    let meta = file.metadata()?;
    let bytes = read_capped(&mut file, &meta)?;
    Ok((bytes, meta))
}

/// Read all of `file` (whose `fstat` is `meta`), refusing more than [`MAX_VAULT_FILE_SIZE`]
/// bytes with [`ErrorKind::FileTooLarge`] (see [`read_error`]): checked against the stat
/// before reading, and enforced while reading in case the file grows.
pub(crate) fn read_capped(file: &mut fs::File, meta: &fs::Metadata) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let too_large = || std::io::Error::new(ErrorKind::FileTooLarge, "vault file too large");
    if meta.len() > MAX_VAULT_FILE_SIZE {
        return Err(too_large());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.by_ref()
        .take(MAX_VAULT_FILE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_VAULT_FILE_SIZE {
        return Err(too_large());
    }
    Ok(bytes)
}

/// A read error on vault file `path` as a [`SyncError`]: `FileTooLarge` (from
/// [`read_capped`]) becomes [`SyncError::PrimaryTooLarge`].
pub(crate) fn read_error(path: &Path, e: std::io::Error) -> SyncError {
    if e.kind() == ErrorKind::FileTooLarge {
        SyncError::PrimaryTooLarge(path.to_owned())
    } else {
        SyncError::io(path, e)
    }
}

/// Fingerprint right after our own atomic write. The stat comes from `path` (the rename may
/// have changed ctime), but only if it is still the file we wrote: same inode, mtime and size
/// as the tmp's pre-rename fstat (rename and link keep all three). Otherwise a daemon replaced
/// it in between, and pairing its stat with our hash would make its version look like our
/// echo; then no stat is stored and the next check goes to the hash.
fn fingerprint_after_write(
    path: &Path,
    tmp_stat: Option<&fs::Metadata>,
    bytes: &[u8],
) -> LastWritten {
    use std::os::unix::fs::MetadataExt;
    let post = match fs::metadata(path) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not stat vault; echo check will use the hash");
            None
        }
    };
    let ours = match (tmp_stat, &post) {
        (Some(t), Some(p)) => {
            let same = t.ino() == p.ino()
                && t.dev() == p.dev()
                && t.len() == p.len()
                && t.modified().ok() == p.modified().ok();
            if !same {
                tracing::warn!(path = %path.display(), "vault replaced right after our write; echo check will use the hash");
            }
            same
        }
        _ => false,
    };
    fingerprint(post.as_ref().filter(|_| ours), bytes)
}

/// Size and hash come from the bytes themselves; without a stat only the fast pre-check is
/// lost, never the write that already succeeded.
pub(crate) fn fingerprint(meta: Option<&fs::Metadata>, bytes: &[u8]) -> LastWritten {
    let (mtime, ctime, inode) = meta.map_or((None, None, None), stat_of);
    LastWritten {
        mtime,
        ctime,
        inode,
        size: bytes.len() as u64,
        hash: *blake3::hash(bytes).as_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// The path is replaced (rename, new inode) between open and fstat: the stat and the
    /// bytes still both describe the file that was opened.
    #[test]
    fn read_with_stat_describes_the_opened_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        fs::write(&path, b"ours").unwrap();
        let ino = fs::metadata(&path).unwrap().ino();
        let (bytes, meta) = read_with_stat_hooked(&path, || {
            let other = dir.path().join("other");
            fs::write(&other, b"theirs!").unwrap();
            fs::rename(&other, &path).unwrap();
        })
        .unwrap();
        assert_eq!(bytes, b"ours");
        assert_eq!(meta.ino(), ino);
        assert_ne!(fs::metadata(&path).unwrap().ino(), ino);
        // So a fingerprint from it does not match the replacement.
        let lw = fingerprint(Some(&meta), &bytes);
        assert!(!lw.stat_matches(&fs::metadata(&path).unwrap()));
    }

    /// A daemon replaces the file between our rename and our stat: no stat is recorded.
    #[test]
    fn fingerprint_after_write_drops_the_stat_of_a_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let ours = b"ours".to_vec();
        let tmp_stat = write_atomic_stat(&path, &ours, Mode::Replace)
            .unwrap()
            .tmp_stat;
        let lw = fingerprint_after_write(&path, tmp_stat.as_ref(), &ours);
        assert!(lw.stat_matches(&fs::metadata(&path).unwrap()), "{lw:?}");

        let tmp_stat = write_atomic_stat(&path, &ours, Mode::Replace)
            .unwrap()
            .tmp_stat;
        let other = dir.path().join("other");
        fs::write(&other, b"thei").unwrap();
        fs::rename(&other, &path).unwrap();
        let lw = fingerprint_after_write(&path, tmp_stat.as_ref(), &ours);
        assert_eq!((lw.mtime, lw.ctime, lw.inode), (None, None, None));
        assert!(!lw.stat_matches(&fs::metadata(&path).unwrap()));
        assert_eq!(&lw.hash, blake3::hash(&ours).as_bytes());
    }
    use crate::cloud::NoopHooks;

    /// Another process removes the backup between our checks and our removal: still `Ok`,
    /// still reported.
    #[test]
    fn delete_backup_of_a_vanished_entry_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let pw = SecretString::new("pw".to_owned());
        let mut v = SyncedVault::create(
            &dir.path().join("a.vault"),
            &pw,
            KdfParams::for_tests(),
            Uuid::from_u128(1),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let snap = v.backup_now().unwrap();
        let rx = v.subscribe();
        v.delete_backup_hooked(&snap, || fs::remove_file(&snap).unwrap())
            .unwrap();
        assert!(!snap.exists());
        assert_eq!(rx.try_recv().unwrap(), SyncEvent::BackupDeleted(snap));
    }

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
