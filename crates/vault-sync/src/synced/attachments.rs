//! Attachment methods of [`SyncedVault`] (03 §1.1, §8, v1.1). Blobs are immutable, so the
//! watcher, merge and backups never touch them. `add_attachment` writes one, absorbing a
//! conflicted package copies in the blobs we lack (03 §6), and only orphan cleanup (after a
//! `save` that wrote, and once after `unlock`) deletes one.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use vault_core::attachment::{self, AttachmentError};
use vault_core::{AttachmentRef, Millis, UnlockedVault, Uuid, VaultError};

use super::{DOWNLOAD_TIMEOUT, SyncedVault};
use crate::atomic::{Mode, write_atomic_stream};
use crate::attachments::{self, AttachmentReader, AttachmentState};
use crate::cloud::CloudError;
use crate::error::SyncError;
use crate::event::SyncEvent;
use crate::package;

impl SyncedVault {
    /// `<name>.vault/attachments/`. Created (mode 0700) by the first `add_attachment`.
    pub fn attachments_dir(&self) -> PathBuf {
        attachments::attachments_dir(&self.path)
    }

    /// Encrypt `data` (exactly `size` bytes) into a new blob and add its reference to `item`;
    /// marks the vault dirty and returns the new attachment id (01 §4, 03 §1.1).
    ///
    /// Refuses `size > MAX_ATTACHMENT_SIZE` ([`SyncError::Attachment`] `TooLarge`) before
    /// reading anything, and an unknown `item` before writing anything. The blob is streamed
    /// into `.<id>.bin.tmp-<hex>` (0600), fsynced and renamed to `<id>.bin`; if sealing fails
    /// (input not exactly `size` bytes, read or write error) the tmp is deleted and nothing
    /// changes. Until the next `save` the reference exists only in memory; a crash meanwhile
    /// leaves an unreferenced blob that orphan cleanup deletes after 24 h.
    pub fn add_attachment(
        &mut self,
        item: Uuid,
        name: &str,
        data: impl Read,
        size: u64,
        now: Millis,
    ) -> Result<Uuid, SyncError> {
        let vault = self.unlocked.as_ref().ok_or(SyncError::Locked)?;
        if vault.get(item).is_none() {
            return Err(VaultError::Malformed(format!("unknown item {item}")).into());
        }
        let r = attachment::new_ref(name, size, now)?;
        let vault_id = vault.vault_id();

        let dir = self.attachments_dir();
        package::ensure_dir(&dir)?;
        let id = r.id;
        let blob = attachments::blob_path(&self.path, id);
        // `seal` consumes the reference and hands it back only on success (one ref, one seal).
        let mut sealed = None;
        write_atomic_stream(&blob, Mode::Replace, |file, _tmp| {
            let (r, _len) = attachment::seal(vault_id, r, data, file)?;
            sealed = Some(r);
            Ok(())
        })?;
        // Always `Some` once the write succeeded; never panic over it regardless.
        let Some(r) = sealed else {
            return Err(SyncError::io(
                &blob,
                std::io::Error::other("attachment sealed without a reference"),
            ));
        };

        let vault = self.unlocked.as_mut().ok_or(SyncError::Locked)?;
        if let Err(e) = vault.add_attachment_ref(item, r, now) {
            // Cannot happen after the checks above (fresh random id), but never leave a blob
            // without a reference behind.
            if let Err(rm) = fs::remove_file(&blob) {
                tracing::warn!(path = %blob.display(), error = %rm, "could not remove unreferenced blob");
            }
            return Err(e.into());
        }
        self.dirty = true;
        tracing::debug!(attachment = %id, "added attachment");
        Ok(id)
    }

    /// Stream the decrypted contents of attachment `id` on `item`.
    ///
    /// Calls `ensure_downloaded` on the blob first (up to [`DOWNLOAD_TIMEOUT`]). Errors:
    /// [`SyncError::AttachmentNotDownloaded`] on a download timeout,
    /// [`SyncError::AttachmentMissing`] if the blob does not exist, `Vault(Malformed)` if the
    /// item does not reference `id`, [`SyncError::Locked`]. Tampering is reported by the
    /// reader itself as it reaches the bad chunk (see [`AttachmentReader`]); bytes already
    /// read must then be discarded.
    pub fn open_attachment(&self, item: Uuid, id: Uuid) -> Result<AttachmentReader, SyncError> {
        let vault = self.unlocked.as_ref().ok_or(SyncError::Locked)?;
        let r = vault
            .get(item)
            .and_then(|i| i.attachment(id))
            .ok_or(SyncError::AttachmentNotFound { item, id })?
            .clone();
        package::check_dir(&self.attachments_dir())?;
        let path = attachments::blob_path(&self.path, id);
        // Never ask the provider to download through a link (`attachment_state` says Missing).
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_file()) {
            return Err(SyncError::UnsafePackageEntry(path));
        }
        match self.hooks.ensure_downloaded(&path, DOWNLOAD_TIMEOUT) {
            Ok(()) => {}
            Err(CloudError::Timeout) => return Err(SyncError::AttachmentNotDownloaded(id)),
            Err(e) => {
                if !self.hooks.is_evicted(&path) && !path.exists() {
                    return Err(SyncError::AttachmentMissing(id));
                }
                return Err(e.into());
            }
        }
        // Never through a symlink; only a regular file.
        let file = match package::open_regular(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(SyncError::AttachmentMissing(id));
            }
            Err(e) if package::is_unsafe_entry(&e) => {
                return Err(SyncError::UnsafePackageEntry(path));
            }
            Err(e) => return Err(SyncError::io(&path, e)),
        };
        AttachmentReader::spawn(vault.vault_id(), r, file, path)
    }

    /// Whether the blob for `id` is on disk, evicted to the cloud, or absent. No decryption,
    /// no download; works while locked. A blob that cannot be stat'ed counts as `Missing`.
    ///
    /// An entry that is a symlink or anything but a regular file is `Missing` too, decided
    /// on the `lstat` before the cloud hook is asked, so it is never reported as
    /// `NotDownloaded` (a download would not fix it, and the hook might follow the link).
    /// `open_attachment` refuses such an entry with [`SyncError::UnsafePackageEntry`]; the
    /// app does not open a `Missing` attachment, so the two never disagree in the UI.
    pub fn attachment_state(&self, id: Uuid) -> AttachmentState {
        let path = attachments::blob_path(&self.path, id);
        match fs::symlink_metadata(&path) {
            Ok(m) if !m.file_type().is_file() => AttachmentState::Missing,
            _ if self.hooks.is_evicted(&path) => AttachmentState::NotDownloaded,
            Ok(_) => AttachmentState::Present,
            Err(_) => AttachmentState::Missing,
        }
    }

    /// Drop the reference to attachment `id` from `item` and mark the vault dirty. The blob
    /// stays until orphan cleanup (24 h after its mtime, once no item references it).
    ///
    /// Core records a removal tombstone, so the removal survives merging with a peer that
    /// still holds the reference.
    pub fn remove_attachment(
        &mut self,
        item: Uuid,
        id: Uuid,
        now: Millis,
    ) -> Result<(), SyncError> {
        let vault = self.unlocked.as_mut().ok_or(SyncError::Locked)?;
        vault.remove_attachment_ref(item, id, now)?;
        self.dirty = true;
        Ok(())
    }

    /// Tests only: pretend orphan cleanup runs `offset` in the future. File ages count from
    /// `max(mtime, ctime)` and ctime cannot be set back, so tests cannot age files otherwise.
    /// Only with the `test-support` feature; release builds always prune on the real clock.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn set_prune_clock_offset_for_tests(&mut self, offset: std::time::Duration) {
        self.prune_clock_offset = offset;
    }

    /// Orphan cleanup (03 §1.1), run after a save that wrote the file and once after a
    /// successful unlock, when disk and memory agree. Failures are logged, never returned.
    pub(super) fn prune_orphan_attachments(&self) {
        let Some(vault) = &self.unlocked else {
            return;
        };
        let referenced: HashSet<Uuid> = vault.attachment_ids().collect();
        let now = SystemTime::now() + self.prune_clock_offset;
        match attachments::prune(&self.attachments_dir(), &referenced, now) {
            Ok(0) => {}
            Ok(n) => self.emit(SyncEvent::AttachmentsPruned(n)),
            Err(e) => tracing::warn!(error = %e, "attachment orphan cleanup failed"),
        }
    }

    /// 03 §6: copy the blobs in `from`'s `attachments/` that `wanted` lists and we lack into
    /// ours (atomic, 0600, never replacing an existing blob). `wanted` maps each attachment id
    /// an authenticated vault references to that reference (see [`wanted_blobs`]); any other
    /// file is ignored, so a planted package cannot make us copy arbitrary data.
    ///
    /// Nothing is published unverified: a source must be exactly the sealed length its
    /// reference implies ([`sealed_len`]; checked on the lstat, so a wrong-sized evicted file
    /// is never downloaded, and again on the open handle), and while it is streamed into the
    /// tmp every chunk is authenticated with the reference's key ([`attachment::open`] into a
    /// sink; core wipes each plaintext chunk, nothing is retained). A short, long, forged or
    /// wrong-key blob is skipped with a warning and its tmp deleted; the package is left where
    /// it is, so a valid copy arriving later is still taken.
    ///
    /// An existing destination is kept as is ("immutable once present"): every blob this
    /// function publishes has passed the check above, and `add_attachment` seals its own.
    /// Blobs copied from conflicted packages before 2026-11-06 were only size-bounded and
    /// are not re-verified here; a corrupt one is still caught by the reader's AEAD check
    /// (reported as tampered) and, once unreferenced, by orphan cleanup.
    ///
    /// Each source is downloaded first; any other failure (I/O, cloud) stops the copy and is
    /// returned so the caller leaves the conflicted package in place. Returns the number of
    /// blobs copied.
    pub(super) fn copy_missing_blobs(
        &self,
        from: &Path,
        wanted: &HashMap<Uuid, &AttachmentRef>,
    ) -> Result<usize, SyncError> {
        let src_dir = package::attachments_dir(from);
        if wanted.is_empty() || !package::check_dir(&src_dir)? {
            return Ok(0);
        }
        let entries = match fs::read_dir(&src_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(SyncError::io(&src_dir, e)),
        };
        let vault_id = self.locked.vault_id();
        let mut copied = 0;
        for entry in entries {
            let entry = entry.map_err(|e| SyncError::io(&src_dir, e))?;
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(attachments::parse_blob_name) else {
                continue;
            };
            let Some(&r) = wanted.get(&id) else {
                tracing::debug!(attachment = %id, "not copying an unreferenced blob");
                continue;
            };
            let expected = sealed_len(r);
            let src = entry.path();
            let dst = attachments::blob_path(&self.path, id);
            if fs::symlink_metadata(&dst).is_ok() || self.hooks.is_evicted(&dst) {
                continue;
            }
            let evicted = self.hooks.is_evicted(&src);
            match fs::symlink_metadata(&src) {
                // A dataless (evicted) file reports its logical size, so this also stops a
                // download of a blob that cannot be the referenced one.
                Ok(m) if m.is_file() && m.len() != expected => {
                    tracing::warn!(path = %src.display(), size = m.len(), expected, "skipping a blob of the wrong size");
                    continue;
                }
                Ok(m) if m.is_file() => {}
                _ if evicted => {}
                _ => continue,
            }
            self.hooks.ensure_downloaded(&src, DOWNLOAD_TIMEOUT)?;
            // Re-checked on the handle: the entry may have become a symlink since the lstat.
            let input = package::open_regular(&src).map_err(|e| {
                if package::is_unsafe_entry(&e) {
                    SyncError::UnsafePackageEntry(src.clone())
                } else {
                    SyncError::io(&src, e)
                }
            })?;
            let len = input.metadata().map_err(|e| SyncError::io(&src, e))?.len();
            if len != expected {
                tracing::warn!(path = %src.display(), size = len, expected, "skipping a blob of the wrong size");
                continue;
            }
            package::ensure_dir(&self.attachments_dir())?;
            let mut rejected = false;
            // Bounded even if the source grows while being copied.
            let mut input = input.take(expected + 1);
            let result = write_atomic_stream(&dst, Mode::NoReplace, |file, tmp| {
                let mut tee = Tee {
                    inner: &mut input,
                    out: file,
                    written: 0,
                };
                match attachment::open(vault_id, r, &mut tee, std::io::sink()) {
                    Ok(()) if tee.written == expected => Ok(()),
                    Ok(()) | Err(AttachmentError::Tampered | AttachmentError::InvalidRef(_)) => {
                        rejected = true;
                        Err(SyncError::io(
                            &src,
                            std::io::Error::new(ErrorKind::InvalidData, "blob failed verification"),
                        ))
                    }
                    Err(AttachmentError::Io(e)) => Err(SyncError::io(tmp, e)),
                    Err(e) => Err(SyncError::io(tmp, std::io::Error::other(e.to_string()))),
                }
            });
            match result {
                Ok(()) => {
                    copied += 1;
                    tracing::debug!(attachment = %id, "copied verified blob from conflicted package");
                }
                // Raced with another copy of the same immutable blob.
                Err(SyncError::AlreadyExists(_)) => {}
                // The tmp is already gone; never published.
                Err(_) if rejected => {
                    tracing::warn!(path = %src.display(), attachment = %id, "skipping a blob that does not authenticate against its reference");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(copied)
    }
}

/// Copies everything read from `inner` into `out` as it is read, so the bytes that
/// [`attachment::open`] authenticates are exactly the bytes written to the tmp.
struct Tee<'a, R> {
    inner: R,
    out: &'a mut fs::File,
    written: u64,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.out.write_all(&buf[..n])?;
        self.written += n as u64;
        Ok(n)
    }
}

/// Exact size of the sealed blob for `r`: the plaintext size plus one AEAD tag per chunk
/// (01 §4). Parsed references are validated (`size <= MAX_ATTACHMENT_SIZE`, nonce count), so
/// this never exceeds `MAX_ATTACHMENT_SIZE` plus its chunk overhead.
pub(super) fn sealed_len(r: &AttachmentRef) -> u64 {
    /// Poly1305 tag per chunk (01 §4: `ct_i = chunk_i + 16-byte tag`).
    const TAG_LEN: u64 = 16;
    let size = r.size.min(attachment::MAX_ATTACHMENT_SIZE);
    size + attachment::chunk_count(size) * TAG_LEN
}

/// Every attachment reference in `vaults` (live items and tombstoned ones) by id. When two
/// vaults hold a reference with the same id, the first vault's wins (callers pass ours
/// first).
pub(super) fn wanted_blobs<'a>(vaults: &[&'a UnlockedVault]) -> HashMap<Uuid, &'a AttachmentRef> {
    let mut out = HashMap::new();
    for r in vaults
        .iter()
        .flat_map(|v| v.items_including_deleted())
        .flat_map(|item| item.attachments.iter())
    {
        out.entry(r.id).or_insert(r);
    }
    out
}
