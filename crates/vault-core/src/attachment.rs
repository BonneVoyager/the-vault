//! Attachment blobs (`01-vault-format.md` §4 "Attachments (v1.1)"): streaming seal / open of
//! one immutable encrypted file per [`AttachmentRef`].
//!
//! Bytes in, bytes out: the helpers take any [`Read`] / [`Write`] and never open files. The
//! blob layout is
//!
//! ```text
//! chunk_size  = 1 MiB; the last chunk may be shorter; a 0-byte file has one empty chunk
//! chunk_count = len(ref.chunk_nonces) = max(1, ceil(size / chunk_size))
//! blob        = ct_0 || ct_1 || ... || ct_{n-1}       (ct_i = chunk_i + 16-byte tag)
//! ct_i        = XChaCha20-Poly1305(key = ref.key, nonce = ref.chunk_nonces[i], chunk_i,
//!                 AAD = vault_id || ref.id || i_be32 || chunk_count_be32 || attachment_version_be16)
//! ```
//!
//! The AAD ([`crate::format::attachment_chunk_aad`]) binds every chunk to its vault, its
//! attachment, its position and the total count, so chunks cannot be swapped, reordered,
//! truncated, extended or moved between vaults: every such change is reported as
//! [`AttachmentError::Tampered`]. Only the AEAD tag check compares secrets; there is no
//! comparison code of our own.
//!
//! # Spec interpretations
//!
//! - The version bound into the AAD is [`ATTACHMENT_VERSION`], a constant of the blob
//!   layout, **not** the vault file's `format_version`: blobs are immutable and must keep
//!   opening after a `FORMAT_VERSION` bump without being re-sealed. (For v1 files the two
//!   values coincide, so blobs sealed before this rule are unaffected.)
//! - [`open`] trusts nothing about the blob except what the reference says: it reads
//!   `chunk_count` ciphertext chunks, verifies each, and then requires end of input and a
//!   total plaintext length equal to `ref.size`. A reference whose nonce count disagrees with
//!   the blob therefore fails as `Tampered`, not as a reference error.
//! - [`seal`] requires the reference to be self-consistent (`new_ref` guarantees this) and the
//!   input to be exactly `ref.size` bytes; a shorter or longer input is
//!   [`AttachmentError::SizeMismatch`] and the partial blob must be discarded.
//! - **One reference, one seal.** `seal` consumes the reference and hands it back only on
//!   success, so a key/nonce pair can never encrypt two different plaintexts (a retry after
//!   an I/O error or size mismatch must start over with a fresh [`new_ref`]).
//! - **Output on error is partial.** Both helpers stream, so by the time a late chunk fails
//!   earlier chunks have already been written to `out`. Callers must treat `out` as garbage on
//!   `Err` (write to a temporary and rename, or delete it). Plaintext chunks that failed their
//!   tag are never written.
//! - Chunk buffers are `Zeroizing`; each plaintext chunk is wiped as soon as it is sealed or
//!   written.

use std::io::{self, Read, Write};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, NONCE_LEN, TAG_LEN};
use crate::format::attachment_chunk_aad;
use crate::item::{AttachmentRef, Millis};

/// Version of the blob layout, bound into every chunk's AAD. Independent of the vault file's
/// `FORMAT_VERSION` so existing blobs survive a file format bump; bump this only when the
/// chunk layout or AAD composition changes (which would require re-sealing every blob).
pub const ATTACHMENT_VERSION: u16 = 1;
/// Plaintext bytes per chunk (1 MiB).
pub const CHUNK_SIZE: usize = 1_048_576;
/// Largest `size` a reference may carry (100 MB). Larger files are refused by [`new_ref`]
/// and rejected by the parser.
pub const MAX_ATTACHMENT_SIZE: u64 = 100_000_000;

/// Chunks a `size`-byte attachment is split into: `max(1, ceil(size / CHUNK_SIZE))`.
pub fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE as u64).max(1)
}

/// Blob file name for an attachment id: 32 lowercase hex digits plus `.bin`.
pub fn blob_file_name(id: Uuid) -> String {
    format!("{}.bin", id.as_simple())
}

/// Everything [`new_ref`], [`seal`] and [`open`] can report.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    /// `size` exceeds [`MAX_ATTACHMENT_SIZE`]; refused before any encryption.
    #[error("attachment of {size} bytes exceeds the {MAX_ATTACHMENT_SIZE}-byte limit")]
    TooLarge { size: u64 },
    /// `seal` read a different number of plaintext bytes than `ref.size`. `actual` is the
    /// number of bytes consumed when the mismatch was detected: less than `expected` for a
    /// short input, `expected + 1` for a long one (reading stops at the first surplus byte).
    #[error("attachment input is {actual} bytes, reference says {expected}")]
    SizeMismatch { expected: u64, actual: u64 },
    /// The reference itself is inconsistent (nonce count does not match `size`, no nonces,
    /// or more chunks than fit a `u32`). Cannot happen for a reference from [`new_ref`] or
    /// from a parsed vault.
    #[error("attachment reference is inconsistent: {0}")]
    InvalidRef(&'static str),
    /// A chunk failed its tag, the blob has the wrong number of chunks, trailing bytes, a
    /// short last chunk, or the decrypted length differs from `ref.size`. Also what a blob
    /// sealed under another vault, attachment id or attachment version produces.
    #[error("attachment blob is corrupt or does not belong to this reference")]
    Tampered,
    /// The reader or writer failed.
    #[error("attachment i/o error: {0}")]
    Io(#[from] io::Error),
}

/// A fresh reference for a `size`-byte file: random v4 id, random 32-byte key and one random
/// nonce per chunk, all from `OsRng`. `added_at = now`.
///
/// # Errors
///
/// [`AttachmentError::TooLarge`] if `size > MAX_ATTACHMENT_SIZE`.
pub fn new_ref(name: &str, size: u64, now: Millis) -> Result<AttachmentRef, AttachmentError> {
    if size > MAX_ATTACHMENT_SIZE {
        return Err(AttachmentError::TooLarge { size });
    }
    // At most 96 chunks after the cap check, so the cast cannot truncate.
    let n = chunk_count(size) as usize;
    Ok(AttachmentRef {
        id: Uuid::new_v4(),
        name: name.to_owned(),
        size,
        key: crypto::random_key(),
        chunk_nonces: (0..n).map(|_| crypto::random_nonce()).collect(),
        added_at: now,
        extras: Vec::new(),
    })
}

/// Check the two invariants of 01 §4 a reference must satisfy to ever match a blob:
/// `size <= MAX_ATTACHMENT_SIZE` and `chunk_nonces.len() == chunk_count(size)`. Everything
/// that puts a reference into a vault (`add_attachment_ref`, `insert`, `update`, the
/// parser) and [`seal`] run this; [`new_ref`] output always passes.
///
/// # Errors
///
/// [`AttachmentError::TooLarge`] or [`AttachmentError::InvalidRef`].
pub fn validate_ref(r: &AttachmentRef) -> Result<(), AttachmentError> {
    if r.size > MAX_ATTACHMENT_SIZE {
        return Err(AttachmentError::TooLarge { size: r.size });
    }
    if r.chunk_nonces.len() as u64 != chunk_count(r.size) {
        return Err(AttachmentError::InvalidRef(
            "chunk_nonces count does not match size",
        ));
    }
    Ok(())
}

/// Validate a reference for sealing and return its chunk count.
fn checked_chunk_count(r: &AttachmentRef) -> Result<u32, AttachmentError> {
    validate_ref(r)?;
    nonce_count(r)
}

/// `chunk_nonces.len()` as the `u32` the AAD carries; at least one.
fn nonce_count(r: &AttachmentRef) -> Result<u32, AttachmentError> {
    if r.chunk_nonces.is_empty() {
        return Err(AttachmentError::InvalidRef("no chunk nonces"));
    }
    u32::try_from(r.chunk_nonces.len()).map_err(|_| AttachmentError::InvalidRef("too many chunks"))
}

/// Plaintext length of chunk `i` of `n` for a `size`-byte file.
fn plain_len(size: u64, i: u32, n: u32) -> usize {
    if i + 1 < n {
        CHUNK_SIZE
    } else {
        // The last chunk: whatever is left after n-1 full chunks (0 for an empty file).
        (size - u64::from(n - 1) * CHUNK_SIZE as u64) as usize
    }
}

/// Fill `buf` as far as the reader allows. Returns the number of bytes read; less than
/// `buf.len()` means end of input.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// `true` if the reader has at least one more byte.
fn has_more<R: Read>(r: &mut R) -> io::Result<bool> {
    let mut probe = [0u8; 1];
    Ok(read_full(r, &mut probe)? == 1)
}

/// Encrypt `plain` (exactly `r.size` bytes) chunk by chunk into `out`. Returns the reference
/// (unchanged) together with the number of blob bytes written (`r.size + 16 * chunk_count`);
/// `out` is flushed on success.
///
/// The reference is taken by value and only returned on success: **one reference, one
/// seal**. A retry after any error needs a new reference from [`new_ref`] (fresh key and
/// nonces); re-sealing different bytes under the same key/nonce pairs would break the AEAD.
///
/// # Errors
///
/// - [`AttachmentError::TooLarge`] / [`AttachmentError::InvalidRef`] if the reference is not
///   one [`new_ref`] would produce.
/// - [`AttachmentError::SizeMismatch`] if `plain` ends before `r.size` bytes or has bytes
///   past it. The blob written so far is unusable; discard it.
/// - [`AttachmentError::Io`] from the reader or writer.
pub fn seal<R: Read, W: Write>(
    vault_id: Uuid,
    r: AttachmentRef,
    mut plain: R,
    mut out: W,
) -> Result<(AttachmentRef, u64), AttachmentError> {
    let n = checked_chunk_count(&r)?;
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut consumed = 0u64;
    let mut written = 0u64;
    for i in 0..n {
        let want = plain_len(r.size, i, n);
        let got = read_full(&mut plain, &mut buf[..want])?;
        consumed += got as u64;
        if got < want {
            return Err(AttachmentError::SizeMismatch {
                expected: r.size,
                actual: consumed,
            });
        }
        let aad = attachment_chunk_aad(ATTACHMENT_VERSION, vault_id, r.id, i, n);
        let nonce: &[u8; NONCE_LEN] = &r.chunk_nonces[i as usize];
        let ct = crypto::seal(&r.key, nonce, &aad, &buf[..want]);
        out.write_all(&ct)?;
        written += ct.len() as u64;
    }
    if has_more(&mut plain)? {
        return Err(AttachmentError::SizeMismatch {
            expected: r.size,
            actual: r.size + 1,
        });
    }
    out.flush()?;
    Ok((r, written))
}

/// Decrypt and verify `blob` chunk by chunk into `out`. Every chunk's tag is checked before
/// its plaintext is written; the blob must contain exactly `r.chunk_nonces.len()` chunks and
/// decrypt to exactly `r.size` bytes. `out` is flushed on success.
///
/// # Errors
///
/// - [`AttachmentError::Tampered`] for any tag failure, a short blob (missing or truncated
///   last chunk), trailing bytes, or a decrypted length other than `r.size`. **Chunks before
///   the failing one have already been written to `out`**; callers must discard the output.
/// - [`AttachmentError::InvalidRef`] if the reference has no nonces (nothing to verify
///   against).
/// - [`AttachmentError::Io`] from the reader or writer.
pub fn open<R: Read, W: Write>(
    vault_id: Uuid,
    r: &AttachmentRef,
    mut blob: R,
    mut out: W,
) -> Result<(), AttachmentError> {
    let n = nonce_count(r)?;
    let full = CHUNK_SIZE + TAG_LEN;
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; full]);
    let mut total = 0u64;
    for i in 0..n {
        let last = i + 1 == n;
        let got = read_full(&mut blob, &mut buf)?;
        if !last && got < full {
            return Err(AttachmentError::Tampered);
        }
        if last {
            if got < TAG_LEN {
                return Err(AttachmentError::Tampered);
            }
            // The last chunk is at most a full chunk; anything after it is foreign.
            if got == full && has_more(&mut blob)? {
                return Err(AttachmentError::Tampered);
            }
        }
        let aad = attachment_chunk_aad(ATTACHMENT_VERSION, vault_id, r.id, i, n);
        let nonce: &[u8; NONCE_LEN] = &r.chunk_nonces[i as usize];
        let pt = crypto::open(&r.key, nonce, &aad, &buf[..got]).ok_or(AttachmentError::Tampered)?;
        total += pt.len() as u64;
        out.write_all(&pt)?;
    }
    if total != r.size {
        return Err(AttachmentError::Tampered);
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_count_rule() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64 + 1), 2);
        assert_eq!(chunk_count(2 * CHUNK_SIZE as u64 + 7), 3);
        assert_eq!(chunk_count(MAX_ATTACHMENT_SIZE), 96);
    }

    #[test]
    fn plain_len_rule() {
        assert_eq!(plain_len(0, 0, 1), 0);
        assert_eq!(plain_len(CHUNK_SIZE as u64, 0, 1), CHUNK_SIZE);
        assert_eq!(plain_len(CHUNK_SIZE as u64 + 1, 0, 2), CHUNK_SIZE);
        assert_eq!(plain_len(CHUNK_SIZE as u64 + 1, 1, 2), 1);
    }

    #[test]
    fn new_refs_never_share_key_or_nonces() {
        let a = new_ref("a", 2 * CHUNK_SIZE as u64 + 1, 1).unwrap();
        let b = new_ref("b", 2 * CHUNK_SIZE as u64 + 1, 1).unwrap();
        assert_ne!(a.id, b.id);
        assert_ne!(a.key.as_ref(), b.key.as_ref());
        for (i, x) in a.chunk_nonces.iter().enumerate() {
            for (j, y) in a.chunk_nonces.iter().chain(&b.chunk_nonces).enumerate() {
                if i != j {
                    assert_ne!(x, y, "nonce {i} repeats at {j}");
                }
            }
        }
    }

    #[test]
    fn validate_ref_rule() {
        let mut r = new_ref("a", 5, 1).unwrap();
        assert!(validate_ref(&r).is_ok());
        r.chunk_nonces.push([0; 24]);
        assert!(matches!(
            validate_ref(&r),
            Err(AttachmentError::InvalidRef(_))
        ));
        r.chunk_nonces.clear();
        assert!(matches!(
            validate_ref(&r),
            Err(AttachmentError::InvalidRef(_))
        ));
        let mut r = new_ref("a", 5, 1).unwrap();
        r.size = MAX_ATTACHMENT_SIZE + 1;
        assert!(matches!(
            validate_ref(&r),
            Err(AttachmentError::TooLarge { .. })
        ));
    }

    #[test]
    fn blob_file_name_is_simple_hex() {
        let id = Uuid::from_bytes([0xAB; 16]);
        assert_eq!(blob_file_name(id), "abababababababababababababababab.bin");
    }

    #[test]
    fn new_ref_shapes() {
        let r = new_ref("a", 0, 5).unwrap();
        assert_eq!(r.chunk_nonces.len(), 1);
        assert_eq!(r.added_at, 5);
        assert_eq!(r.name, "a");
        let r = new_ref("b", 2 * CHUNK_SIZE as u64 + 7, 5).unwrap();
        assert_eq!(r.chunk_nonces.len(), 3);
        assert!(matches!(
            new_ref("c", MAX_ATTACHMENT_SIZE + 1, 5),
            Err(AttachmentError::TooLarge { .. })
        ));
        assert!(new_ref("d", MAX_ATTACHMENT_SIZE, 5).is_ok());
    }
}
