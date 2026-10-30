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

use std::collections::HashSet;
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

/// An unreferenced blob is deleted by orphan cleanup only once its mtime is older than this
/// (03 §1.1): it may belong to an item that has not synced yet.
pub const ORPHAN_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// A leftover `.<id>.bin.tmp-<hex>` (crashed `add_attachment`) is deleted by orphan cleanup
/// once its mtime is older than this.
pub const STALE_TMP_GRACE: Duration = Duration::from_secs(60 * 60);

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

/// Delete orphaned blobs and stale tmp files in `dir` (03 §1.1). A `*.bin` whose id is not in
/// `referenced` goes once its age (from `max(mtime, ctime)`, see the module docs) exceeds
/// [`ORPHAN_GRACE`]; a blob tmp once it exceeds [`STALE_TMP_GRACE`]. Anything else (other
/// names, directories, symlinks, files stamped in the future or unreadable) is left alone. A missing directory is not an error. Returns the number
/// of blobs deleted; individual delete failures are logged and skipped.
pub(crate) fn prune(
    dir: &Path,
    referenced: &HashSet<Uuid>,
    now: SystemTime,
) -> Result<usize, SyncError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(SyncError::io(dir, e)),
    };
    let older_than = |path: &Path, grace: Duration| -> bool {
        match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_file() => newest_stamp(&m)
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > grace),
            _ => false,
        }
    };
    let mut pruned = 0;
    for entry in entries {
        let entry = entry.map_err(|e| SyncError::io(dir, e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = entry.path();
        let (is_blob, grace) = match parse_blob_name(name) {
            Some(id) if !referenced.contains(&id) => (true, ORPHAN_GRACE),
            Some(_) => continue,
            None if is_blob_tmp(name) => (false, STALE_TMP_GRACE),
            None => continue,
        };
        if !older_than(&path, grace) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "pruned attachment file");
                pruned += usize::from(is_blob);
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "could not prune attachment file");
            }
        }
    }
    Ok(pruned)
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
        let none = HashSet::new();
        assert_eq!(prune(dir.path(), &none, SystemTime::now()).unwrap(), 0);
        assert!(orphan.exists());
        let later = SystemTime::now() + ORPHAN_GRACE + Duration::from_secs(60);
        assert_eq!(prune(dir.path(), &none, later).unwrap(), 1);
        assert!(!orphan.exists());
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
