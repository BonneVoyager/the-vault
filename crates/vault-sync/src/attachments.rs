//! Attachment blobs on disk (03 §1.1): the package's `attachments/` directory, the
//! streaming [`AttachmentReader`], and orphan cleanup. The `SyncedVault` methods that use
//! these live in `synced/attachments.rs`.
//!
//! Decryption is vault-core's [`attachment::open`], which pushes verified plaintext chunks
//! into a `Write`. To offer a pull-based `Read` without holding the whole blob, the reader runs
//! `open` on a helper thread that hands over one chunk at a time through a rendezvous-sized
//! channel; at most about four 1 MiB chunks exist at once (core's working buffer, the copy
//! being sent, the channel slot, the reader's current chunk), all wiped on drop.
//!
//! # Orphan age
//!
//! Orphan cleanup measures a file's age from `max(mtime, ctime)`, not mtime alone. Dropbox and
//! iCloud preserve the source device's mtime, so a peer's blob that arrives before the vault
//! file referencing it can carry an mtime days old; judged by mtime it would be deleted, and
//! the deletion would sync back to the peer. ctime is set locally whenever the file is
//! created, renamed or has its metadata changed, and userspace cannot set it, so a blob that
//! just arrived always counts as fresh.
//!
//! # Quarantine (security review 2026-11-26, M-02)
//!
//! Orphan cleanup never deletes a blob outright. An orphan past [`ORPHAN_GRACE`] is moved into
//! `attachments/orphaned/` under its own name, and only deleted from there once it has been
//! in quarantine for more than [`QUARANTINE_GRACE`]. A stale but authentic `vault.bin` (from
//! a provider's version history, or a provider resolving a conflict the wrong way) therefore
//! cannot make cleanup destroy the blobs added since: restoring the newest snapshot, or a
//! merge that brings the reference back, moves the blob back out ([`restore_quarantined`]).
//! Rename refreshes ctime, so the quarantine age counts from the move (or from a peer's
//! arrival).

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use crossbeam_channel::{Receiver, Sender};
use vault_core::attachment::{self, AttachmentError};
use vault_core::{AttachmentRef, Uuid};
use zeroize::Zeroizing;

use crate::error::SyncError;
use crate::package;

/// An unreferenced blob is moved into quarantine by orphan cleanup only once it has been
/// present locally (from `max(mtime, ctime)`) for longer than this (03 §1.1): it may belong to
/// an item that has not synced yet. Deletion follows only after [`QUARANTINE_GRACE`].
pub const ORPHAN_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// A leftover `.<id>.bin.tmp-<hex>` (crashed `add_attachment`) is deleted by orphan cleanup
/// once its mtime is older than this.
pub const STALE_TMP_GRACE: Duration = Duration::from_secs(60 * 60);

/// A blob in quarantine (`attachments/orphaned/`) is deleted once it has been there (measured
/// like [`ORPHAN_GRACE`], from `max(mtime, ctime)`; the move refreshes ctime) for longer than
/// this: 30 days, matching Recently Deleted (02), so a rollback noticed within a month loses
/// nothing (security review 2026-11-26, M-02).
pub const QUARANTINE_GRACE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Name of the quarantine directory inside `attachments/`. No leading dot, so providers that
/// skip hidden entries still sync it; it cannot clash with a blob name (`<32 hex>.bin`).
pub const QUARANTINE_DIR_NAME: &str = "orphaned";

/// A quarantined blob whose name is taken gets the lowest free suffix `<id>.bin.<n>`,
/// `1 <= n <= MAX_QUARANTINE_COPIES`; past that it stays where it is (logged).
const MAX_QUARANTINE_COPIES: u32 = 16;

/// Where an attachment's blob stands locally (03 §1.1). Never an error that blocks the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentState {
    /// The blob file is on disk.
    Present,
    /// The cloud provider evicted the blob; `open_attachment` will try to download it.
    NotDownloaded,
    /// No blob file (not synced yet, deleted, or restored from a backup without it).
    Missing,
}

/// `<name>.vault/attachments`.
pub(crate) fn attachments_dir(package: &Path) -> PathBuf {
    package::attachments_dir(package)
}

/// `<attachments dir>/<32 lowercase hex>.bin`.
pub(crate) fn blob_path(package: &Path, id: Uuid) -> PathBuf {
    attachments_dir(package).join(attachment::blob_file_name(id))
}

/// The attachment id of a blob file name, only if `name` is exactly what
/// [`attachment::blob_file_name`] produces (lowercase, no dashes).
pub(crate) fn parse_blob_name(name: &str) -> Option<Uuid> {
    let hex = name.strip_suffix(".bin")?;
    if hex.len() != 32 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Uuid::try_parse(hex).ok()
}

/// `<attachments dir>/orphaned`.
pub(crate) fn quarantine_dir(attachments_dir: &Path) -> PathBuf {
    attachments_dir.join(QUARANTINE_DIR_NAME)
}

/// Name of quarantined copy `n` of blob `id`: `<id>.bin` for 0, `<id>.bin.<n>` otherwise.
fn quarantined_name(id: Uuid, n: u32) -> String {
    let base = attachment::blob_file_name(id);
    if n == 0 { base } else { format!("{base}.{n}") }
}

/// The `(id, n)` of a name [`quarantined_name`] produces; anything else is `None`.
fn parse_quarantined_name(name: &str) -> Option<(Uuid, u32)> {
    if let Some(id) = parse_blob_name(name) {
        return Some((id, 0));
    }
    let (base, n) = name.rsplit_once('.')?;
    if n.is_empty() || n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = n.parse().ok()?;
    (n <= MAX_QUARANTINE_COPIES)
        .then(|| parse_blob_name(base).map(|id| (id, n)))
        .flatten()
}

/// `.<32 hex>.bin.tmp-<8 hex>`, the tmp name `write_atomic_stream` uses for a blob.
fn is_blob_tmp(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.split_once(".tmp-"))
        .is_some_and(|(blob, _)| parse_blob_name(blob).is_some())
}

/// Local arrival time of a file: the later of mtime and ctime (see the module docs). `None`
/// when neither is readable.
fn newest_stamp(m: &fs::Metadata) -> Option<SystemTime> {
    use std::os::unix::fs::MetadataExt;
    let ctime = u64::try_from(m.ctime()).ok().and_then(|secs| {
        let nanos = u32::try_from(m.ctime_nsec()).ok()?;
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
    });
    match (m.modified().ok(), ctime) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// Whether `path` is a regular file (not a symlink) present locally for longer than `grace`
/// at `now`. Future-dated or unreadable files are never old.
fn older_than(path: &Path, grace: Duration, now: SystemTime) -> bool {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => newest_stamp(&m)
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > grace),
        _ => false,
    }
}

/// `.vault.bin.tmp-<8 hex>`, the tmp name `write_atomic` uses for the primary.
fn is_vault_tmp(name: &str) -> bool {
    name.strip_prefix(&format!(".{}.tmp-", package::VAULT_FILE_NAME))
        .is_some_and(|hex| hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Delete `.vault.bin.tmp-*` files directly in `package` that are older than
/// [`STALE_TMP_GRACE`] (same age rule as blob tmp files): left by a crash between tmp
/// creation and rename (03 §1 "never left behind"). Returns how many were deleted; individual
/// delete failures are logged and skipped.
pub(crate) fn prune_stale_vault_tmp(package: &Path, now: SystemTime) -> Result<usize, SyncError> {
    let entries = match fs::read_dir(package) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(SyncError::io(package, e)),
    };
    let mut pruned = 0;
    for entry in entries {
        let entry = entry.map_err(|e| SyncError::io(package, e))?;
        if !entry.file_name().to_str().is_some_and(is_vault_tmp) {
            continue;
        }
        let path = entry.path();
        if !older_than(&path, STALE_TMP_GRACE, now) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "removed stale vault tmp file");
                pruned += 1;
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "could not remove stale vault tmp file");
            }
        }
    }
    Ok(pruned)
}

/// What one orphan-cleanup pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PruneReport {
    /// Orphans moved into quarantine.
    pub quarantined: usize,
    /// Quarantined blobs moved back because a reference to them exists again.
    pub restored: usize,
    /// Quarantined blobs deleted after [`QUARANTINE_GRACE`].
    pub expired: usize,
}

/// Orphan cleanup in `dir` (03 §1.1), in this order:
///
/// 1. every quarantined blob whose id is in `wanted` goes back ([`restore_quarantined`]);
/// 2. quarantined blobs older than [`QUARANTINE_GRACE`] are deleted;
/// 3. a `*.bin` whose id is not in `wanted` and whose age (from `max(mtime, ctime)`, see the
///    module docs) exceeds [`ORPHAN_GRACE`] is moved into quarantine, never deleted; a blob
///    tmp older than [`STALE_TMP_GRACE`] is deleted.
///
/// `wanted` maps every referenced id to its sealed length. Step 2 runs before step 3, so a
/// blob is never quarantined and expired in one pass. Anything else (other names,
/// directories, symlinks, files stamped in the future or unreadable) is left alone. A missing
/// directory is not an error; a symlinked `attachments/` or `orphaned/` is
/// [`SyncError::UnsafePackageDir`] and nothing is touched. Individual failures are logged and
/// skipped.
pub(crate) fn prune(
    dir: &Path,
    wanted: &HashMap<Uuid, u64>,
    now: SystemTime,
) -> Result<PruneReport, SyncError> {
    // A symlinked `attachments/` is refused, never followed (moves would land outside).
    if !crate::package::check_dir(dir)? {
        return Ok(PruneReport::default());
    }
    let qdir = quarantine_dir(dir);
    let has_quarantine = crate::package::check_dir(&qdir)?;
    let mut report = PruneReport::default();
    if has_quarantine {
        report.restored = restore_quarantined(dir, wanted)?;
        report.expired = expire_quarantine(&qdir, now)?;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(SyncError::io(dir, e)),
    };
    let older_than = |path: &Path, grace: Duration| older_than(path, grace, now);
    for entry in entries {
        let entry = entry.map_err(|e| SyncError::io(dir, e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = entry.path();
        match parse_blob_name(name) {
            Some(id) if !wanted.contains_key(&id) => {
                if older_than(&path, ORPHAN_GRACE) && quarantine_blob(&qdir, &path, id) {
                    report.quarantined += 1;
                }
            }
            Some(_) => {}
            None if is_blob_tmp(name) && older_than(&path, STALE_TMP_GRACE) => {
                match fs::remove_file(&path) {
                    Ok(()) => {
                        tracing::info!(path = %path.display(), "removed stale attachment tmp file")
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "could not remove stale attachment tmp file");
                    }
                }
            }
            None => {}
        }
    }
    Ok(report)
}

/// Move the orphan `path` (blob `id`) into `qdir` (created 0700) as `<id>.bin`, or the lowest
/// free `<id>.bin.<n>` if that is taken, never replacing anything. Returns whether it moved;
/// on any failure the blob stays where it is (logged), it is never deleted here.
fn quarantine_blob(qdir: &Path, path: &Path, id: Uuid) -> bool {
    if let Err(e) = crate::package::ensure_dir(qdir) {
        tracing::warn!(path = %qdir.display(), error = %e, "cannot create the attachment quarantine");
        return false;
    }
    for n in 0..=MAX_QUARANTINE_COPIES {
        let dst = qdir.join(quarantined_name(id, n));
        match crate::atomic::rename_no_replace(path, &dst) {
            Ok(()) => {
                tracing::info!(attachment = %id, path = %dst.display(), "moved orphaned attachment blob into quarantine");
                return true;
            }
            Err(SyncError::AlreadyExists(_)) => {}
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "could not quarantine orphaned attachment blob");
                return false;
            }
        }
    }
    tracing::warn!(attachment = %id, "attachment quarantine has too many copies of this blob; leaving it in place");
    false
}

/// Delete quarantined blobs older than [`QUARANTINE_GRACE`]. Returns how many went.
fn expire_quarantine(qdir: &Path, now: SystemTime) -> Result<usize, SyncError> {
    let entries = match fs::read_dir(qdir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(SyncError::io(qdir, e)),
    };
    let mut expired = 0;
    for entry in entries {
        let entry = entry.map_err(|e| SyncError::io(qdir, e))?;
        if entry
            .file_name()
            .to_str()
            .and_then(parse_quarantined_name)
            .is_none()
        {
            continue;
        }
        let path = entry.path();
        if !older_than(&path, QUARANTINE_GRACE, now) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "deleted quarantined attachment blob after the grace period");
                expired += 1;
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "could not delete quarantined attachment blob");
            }
        }
    }
    Ok(expired)
}

/// Move quarantined blobs whose id is in `wanted` (id -> sealed length) back into `dir`
/// (`attachments/`), unless a blob with that id is already there. Per id the candidate is
/// chosen deterministically: the lowest copy number `n` (plain `<id>.bin` first) whose size
/// equals the sealed length; a copy of the wrong size is never restored (it cannot be the
/// referenced blob) and expires with the rest. Never replaces anything. Returns how many
/// moved back; individual failures are logged and skipped.
pub(crate) fn restore_quarantined(
    dir: &Path,
    wanted: &HashMap<Uuid, u64>,
) -> Result<usize, SyncError> {
    let qdir = quarantine_dir(dir);
    if wanted.is_empty() || !crate::package::check_dir(dir)? || !crate::package::check_dir(&qdir)? {
        return Ok(0);
    }
    let entries = match fs::read_dir(&qdir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(SyncError::io(&qdir, e)),
    };
    // id -> (n, path) of the best candidate so far.
    let mut best: BTreeMap<Uuid, (u32, PathBuf)> = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|e| SyncError::io(&qdir, e))?;
        let Some((id, n)) = entry.file_name().to_str().and_then(parse_quarantined_name) else {
            continue;
        };
        let Some(&len) = wanted.get(&id) else {
            continue;
        };
        let path = entry.path();
        if !fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file() && m.len() == len) {
            continue;
        }
        if best.get(&id).is_none_or(|(m, _)| n < *m) {
            best.insert(id, (n, path));
        }
    }
    let mut restored = 0;
    for (id, (_, src)) in best {
        let dst = dir.join(attachment::blob_file_name(id));
        if fs::symlink_metadata(&dst).is_ok() {
            continue;
        }
        match crate::atomic::rename_no_replace(&src, &dst) {
            Ok(()) => {
                tracing::info!(attachment = %id, "restored a referenced attachment blob from quarantine");
                restored += 1;
            }
            Err(SyncError::AlreadyExists(_)) => {}
            Err(e) => {
                tracing::warn!(path = %src.display(), error = %e, "could not restore attachment blob from quarantine");
            }
        }
    }
    Ok(restored)
}

/// What the decryption thread sends.
enum Msg {
    /// One verified plaintext chunk.
    Chunk(Zeroizing<Vec<u8>>),
    /// `attachment::open` finished; `Ok` means every chunk verified and the size matched.
    End(Result<(), AttachmentError>),
}

/// The `Write` end handed to `attachment::open`: each verified chunk becomes one message.
struct ChunkSink {
    tx: Sender<Msg>,
}

impl Write for ChunkSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let chunk = Zeroizing::new(buf.to_vec());
        // The reader was dropped: stop decrypting.
        self.tx
            .send(Msg::Chunk(chunk))
            .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Streams the decrypted bytes of one attachment (from `SyncedVault::open_attachment`).
///
/// Every byte handed out belongs to a chunk whose tag has already been verified. A blob that
/// is tampered with *after* a good prefix (a later chunk, truncation, trailing bytes) is only
/// detected when that point is reached: `read` then returns an `io::Error` of kind
/// `InvalidData` whose payload (`get_ref()`, downcast to [`SyncError`]) is
/// [`SyncError::AttachmentTampered`], and keeps returning it. **Everything already read must
/// then be discarded** (write to a temporary and only keep it after `read` returned `Ok(0)`).
/// Other failures carry [`SyncError::Io`] or [`SyncError::Attachment`] the same way.
///
/// The current chunk (at most 1 MiB) is held in a `Zeroizing` buffer, wiped when replaced and
/// on drop. Dropping the reader early stops the decryption thread at its next chunk.
pub struct AttachmentReader {
    id: Uuid,
    size: u64,
    path: PathBuf,
    rx: Receiver<Msg>,
    buf: Zeroizing<Vec<u8>>,
    pos: usize,
    /// `Some(Ok)` after a clean end; `Some(Err(kind))` after a failure (repeated on every read).
    end: Option<Result<(), Failure>>,
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    Tampered,
    Io(ErrorKind),
    InvalidRef,
    ThreadGone,
}

impl AttachmentReader {
    /// Start decrypting `blob` (already opened) for reference `r`.
    pub(crate) fn spawn(
        vault_id: Uuid,
        r: AttachmentRef,
        blob: File,
        path: PathBuf,
    ) -> Result<Self, SyncError> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let (id, size) = (r.id, r.size);
        thread::Builder::new()
            .name("vault-attachment-open".to_owned())
            .spawn(move || {
                let sink = ChunkSink { tx: tx.clone() };
                let result = attachment::open(
                    vault_id,
                    &r,
                    BufReader::with_capacity(64 * 1024, blob),
                    sink,
                );
                // The receiver may be gone already; nothing to report to then.
                let _ = tx.send(Msg::End(result));
            })
            .map_err(|e| SyncError::io(&path, e))?;
        Ok(Self {
            id,
            size,
            path,
            rx,
            buf: Zeroizing::new(Vec::new()),
            pos: 0,
            end: None,
        })
    }

    /// The attachment id.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Plaintext length in bytes, as recorded in the reference.
    pub fn size(&self) -> u64 {
        self.size
    }

    fn error(&self, failure: Failure) -> io::Error {
        let (kind, inner) = match failure {
            Failure::Tampered => (
                ErrorKind::InvalidData,
                SyncError::AttachmentTampered(self.id),
            ),
            Failure::InvalidRef => (
                ErrorKind::InvalidData,
                SyncError::Attachment(AttachmentError::InvalidRef("reference does not match blob")),
            ),
            Failure::Io(kind) => (kind, SyncError::io(&self.path, kind.into())),
            Failure::ThreadGone => (
                ErrorKind::Other,
                SyncError::io(
                    &self.path,
                    io::Error::other("attachment decryption stopped unexpectedly"),
                ),
            ),
        };
        io::Error::new(kind, inner)
    }
}

impl Read for AttachmentReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.buf.len() {
                let n = out.len().min(self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.end {
                Some(Ok(())) => return Ok(0),
                Some(Err(f)) => return Err(self.error(f)),
                None => {}
            }
            match self.rx.recv() {
                Ok(Msg::Chunk(chunk)) => {
                    // The previous chunk is wiped as it is dropped here.
                    self.buf = chunk;
                    self.pos = 0;
                }
                Ok(Msg::End(result)) => {
                    self.end = Some(result.map_err(|e| match e {
                        AttachmentError::Tampered => Failure::Tampered,
                        AttachmentError::Io(e) => Failure::Io(e.kind()),
                        _ => Failure::InvalidRef,
                    }));
                    if let Some(Err(f)) = self.end {
                        tracing::warn!(attachment = %self.id, ?f, "attachment read failed");
                    }
                }
                Err(_) => self.end = Some(Err(Failure::ThreadGone)),
            }
        }
    }
}

impl std::fmt::Debug for AttachmentReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentReader")
            .field("id", &self.id)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn blob_names() {
        let id = Uuid::from_u128(0xABCDEF);
        let name = attachment::blob_file_name(id);
        assert_eq!(parse_blob_name(&name), Some(id));
        assert_eq!(
            parse_blob_name(&name.to_uppercase().replace(".BIN", ".bin")),
            None
        );
        assert_eq!(parse_blob_name("abc.bin"), None);
        assert_eq!(parse_blob_name(&format!("{}.bin", id.hyphenated())), None);
        assert!(is_blob_tmp(&format!(".{name}.tmp-0011aabb")));
        assert!(!is_blob_tmp(&format!("{name}.tmp-0011aabb")));
        assert!(!is_blob_tmp(".x.bin.tmp-0011aabb"));
    }

    #[test]
    fn stale_vault_tmp_is_removed_after_an_hour_only() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(".vault.bin.tmp-0011aabb");
        let other = [
            ".vault.bin.tmp-xyz",
            "vault.bin",
            ".lock",
            ".x.bin.tmp-0011aabb",
        ];
        fs::write(&stale, b"x").unwrap();
        for n in other {
            fs::write(dir.path().join(n), b"x").unwrap();
        }
        let now = SystemTime::now();
        assert_eq!(prune_stale_vault_tmp(dir.path(), now).unwrap(), 0);
        assert!(stale.exists());
        let later = now + STALE_TMP_GRACE + Duration::from_secs(60);
        assert_eq!(prune_stale_vault_tmp(dir.path(), later).unwrap(), 1);
        assert!(!stale.exists());
        for n in other {
            assert!(dir.path().join(n).exists(), "{n}");
        }
        assert!(is_vault_tmp(".vault.bin.tmp-DEADbeef"));
        assert!(!is_vault_tmp("vault.bin.tmp-deadbeef"));
    }

    #[test]
    fn prune_counts_age_from_ctime_too() {
        let dir = tempfile::tempdir().unwrap();
        let orphan = dir
            .path()
            .join(attachment::blob_file_name(Uuid::from_u128(7)));
        fs::write(&orphan, b"x").unwrap();
        // A peer's mtime from two days ago; ctime is now (the file just arrived).
        File::options()
            .write(true)
            .open(&orphan)
            .unwrap()
            .set_modified(SystemTime::now() - 2 * ORPHAN_GRACE)
            .unwrap();
        let none = HashMap::new();
        assert_eq!(
            prune(dir.path(), &none, SystemTime::now()).unwrap(),
            PruneReport::default()
        );
        assert!(orphan.exists());
        let later = SystemTime::now() + ORPHAN_GRACE + Duration::from_secs(60);
        assert_eq!(prune(dir.path(), &none, later).unwrap().quarantined, 1);
        assert!(!orphan.exists());
        assert!(
            quarantine_dir(dir.path())
                .join(attachment::blob_file_name(Uuid::from_u128(7)))
                .exists()
        );
    }

    #[test]
    fn quarantine_names() {
        let id = Uuid::from_u128(0xABC);
        assert_eq!(
            parse_quarantined_name(&quarantined_name(id, 0)),
            Some((id, 0))
        );
        assert_eq!(
            parse_quarantined_name(&quarantined_name(id, 3)),
            Some((id, 3))
        );
        let base = attachment::blob_file_name(id);
        for bad in ["x.bin.1", "orphaned", ".bin.1"] {
            assert_eq!(parse_quarantined_name(bad), None, "{bad}");
        }
        for bad in [".0", ".01", ".", ".17", ".1a", ".-1"] {
            assert_eq!(
                parse_quarantined_name(&format!("{base}{bad}")),
                None,
                "{bad}"
            );
        }
    }

    /// Collisions take the lowest free suffix; restore prefers the lowest number of the
    /// right size; expiry deletes only after the second grace period.
    #[test]
    fn quarantine_collisions_restore_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(9);
        let blob = dir.path().join(attachment::blob_file_name(id));
        let qdir = quarantine_dir(dir.path());
        let none = HashMap::new();
        let later = SystemTime::now() + ORPHAN_GRACE + Duration::from_secs(60);
        for content in [&b"first"[..], b"second!", b"third"] {
            fs::write(&blob, content).unwrap();
            assert_eq!(prune(dir.path(), &none, later).unwrap().quarantined, 1);
        }
        let mut names: Vec<String> = fs::read_dir(&qdir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let base = attachment::blob_file_name(id);
        assert_eq!(
            names,
            [base.clone(), format!("{base}.1"), format!("{base}.2")]
        );
        assert_eq!(
            fs::metadata(&qdir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // Wanted with length 5: `<id>.bin` ("first") wins over `.2` ("third"); "second!"
        // (7 bytes) can never be restored for this reference.
        let wanted = HashMap::from([(id, 5)]);
        assert_eq!(restore_quarantined(dir.path(), &wanted).unwrap(), 1);
        assert_eq!(fs::read(&blob).unwrap(), b"first");
        // Present already: nothing moves.
        assert_eq!(restore_quarantined(dir.path(), &wanted).unwrap(), 0);
        assert!(qdir.join(format!("{base}.2")).exists());

        // Expiry: not before QUARANTINE_GRACE, then every copy of an unreferenced id.
        let report = prune(
            dir.path(),
            &wanted,
            SystemTime::now() + QUARANTINE_GRACE - Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(report.expired, 0);
        fs::write(qdir.join("notes.txt"), b"x").unwrap();
        let report = prune(
            dir.path(),
            &wanted,
            SystemTime::now() + QUARANTINE_GRACE + Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(report.expired, 2);
        assert!(blob.exists(), "referenced blob outside quarantine is kept");
        assert!(
            qdir.join("notes.txt").exists(),
            "foreign names are left alone"
        );
    }

    #[test]
    fn symlinked_quarantine_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let blob = dir
            .path()
            .join(attachment::blob_file_name(Uuid::from_u128(4)));
        fs::write(&blob, b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), quarantine_dir(dir.path())).unwrap();
        let later = SystemTime::now() + ORPHAN_GRACE + Duration::from_secs(60);
        let err = prune(dir.path(), &HashMap::new(), later).unwrap_err();
        assert!(matches!(err, SyncError::UnsafePackageDir(_)), "{err:?}");
        assert!(blob.exists());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn dir_layout() {
        let p = Path::new("/x/My.vault");
        assert_eq!(attachments_dir(p), Path::new("/x/My.vault/attachments"));
        let id = Uuid::from_u128(1);
        assert_eq!(
            blob_path(p, id),
            Path::new("/x/My.vault/attachments/00000000000000000000000000000001.bin")
        );
    }
}
