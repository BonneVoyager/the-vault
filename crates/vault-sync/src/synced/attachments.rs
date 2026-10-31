//! Attachment methods of [`SyncedVault`] (03 §1.1, §8, v1.1). Blobs are immutable, so the
//! watcher, merge and backups never touch them. `add_attachment` writes one, absorbing a
//! conflicted package copies in the blobs we lack (03 §6), and only orphan cleanup (after a
//! `save` that wrote, and once after `unlock`) deletes one.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use vault_core::attachment;
use vault_core::{Millis, UnlockedVault, Uuid, VaultError};

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
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(SyncError::AttachmentMissing(id));
            }
            Err(e) => return Err(SyncError::io(&path, e)),
        };
        AttachmentReader::spawn(vault.vault_id(), r, file, path)
    }

    /// Whether the blob for `id` is on disk, evicted to the cloud, or absent. No decryption,
    /// no download; works while locked. A blob that cannot be stat'ed counts as `Missing`.
    pub fn attachment_state(&self, id: Uuid) -> AttachmentState {
        let path = attachments::blob_path(&self.path, id);
        if self.hooks.is_evicted(&path) {
            return AttachmentState::NotDownloaded;
        }
        match fs::metadata(&path) {
            Ok(m) if m.is_file() => AttachmentState::Present,
            _ => AttachmentState::Missing,
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
    /// ours (atomic, 0600, never replacing an existing blob: blobs are immutable, so an
    /// existing one with the same id is the same blob). `wanted` maps each attachment id an
    /// authenticated vault references to the exact size its sealed blob has (see
    /// [`blob_budget`]); any other file is ignored, and a source larger than its budget is
    /// skipped (never downloaded past it, never copied), so a planted package cannot make us
    /// copy arbitrary or unbounded data. Each source is downloaded first; any other failure
    /// stops the copy and is returned so the caller leaves the conflicted package in place.
    /// Returns the number of blobs copied.
    pub(super) fn copy_missing_blobs(
        &self,
        from: &Path,
        wanted: &HashMap<Uuid, u64>,
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
        let mut copied = 0;
        for entry in entries {
            let entry = entry.map_err(|e| SyncError::io(&src_dir, e))?;
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(attachments::parse_blob_name) else {
                continue;
            };
            let Some(&budget) = wanted.get(&id) else {
                tracing::debug!(attachment = %id, "not copying an unreferenced blob");
                continue;
            };
            let src = entry.path();
            let dst = attachments::blob_path(&self.path, id);
            if fs::symlink_metadata(&dst).is_ok() || self.hooks.is_evicted(&dst) {
                continue;
            }
            let evicted = self.hooks.is_evicted(&src);
            match fs::symlink_metadata(&src) {
                // A dataless (evicted) file reports its logical size, so this also stops a
                // download of an oversized blob.
                Ok(m) if m.is_file() && m.len() > budget => {
                    tracing::warn!(path = %src.display(), size = m.len(), budget, "skipping an oversized blob");
                    continue;
                }
                Ok(m) if m.is_file() => {}
                _ if evicted => {}
                _ => continue,
            }
            self.hooks.ensure_downloaded(&src, DOWNLOAD_TIMEOUT)?;
            let input = File::open(&src).map_err(|e| SyncError::io(&src, e))?;
            let len = input.metadata().map_err(|e| SyncError::io(&src, e))?.len();
            if len > budget {
                tracing::warn!(path = %src.display(), size = len, budget, "skipping an oversized blob");
                continue;
            }
            package::ensure_dir(&self.attachments_dir())?;
            // Bounded even if the source grows while being copied.
            let mut input = input.take(budget + 1);
            match write_atomic_stream(&dst, Mode::NoReplace, |file, tmp| {
                let n = std::io::copy(&mut input, file).map_err(|e| SyncError::io(tmp, e))?;
                if n > budget {
                    return Err(SyncError::io(
                        &src,
                        std::io::Error::new(ErrorKind::FileTooLarge, "blob grew while copying"),
                    ));
                }
                Ok(())
            }) {
                Ok(()) => copied += 1,
                // Raced with another copy of the same immutable blob.
                Err(SyncError::AlreadyExists(_)) => {}
                Err(e) => return Err(e),
            }
            tracing::debug!(attachment = %id, "copied blob from conflicted package");
        }
        Ok(copied)
    }
}

/// Every attachment id referenced by `vaults` (live items and tombstoned ones), mapped to the
/// exact size of its sealed blob: the plaintext size plus one AEAD tag per chunk (01 §4).
/// References are validated by the parser (`size <= MAX_ATTACHMENT_SIZE`, nonce count), so
/// no budget exceeds `MAX_ATTACHMENT_SIZE` plus its chunk overhead.
pub(super) fn blob_budget(vaults: &[&UnlockedVault]) -> HashMap<Uuid, u64> {
    /// Poly1305 tag per chunk (01 §4: `ct_i = chunk_i + 16-byte tag`).
    const TAG_LEN: u64 = 16;
    vaults
        .iter()
        .flat_map(|v| v.items_including_deleted())
        .flat_map(|item| item.attachments.iter())
        .map(|r| {
            let size = r.size.min(attachment::MAX_ATTACHMENT_SIZE);
            (r.id, size + attachment::chunk_count(size) * TAG_LEN)
        })
        .collect()
}
