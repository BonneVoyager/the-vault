//! Fixed attachment reference shared by the `attachment_blob` target and the seeder, so the
//! committed seed blob decrypts under exactly the reference the target builds.

use vault_core::attachment::{CHUNK_SIZE, new_ref};
use vault_core::{AttachmentRef, Uuid};

/// Poly1305 tag length appended to every chunk (01 §4).
const TAG_LEN: usize = 16;

pub const VAULT_ID: Uuid = Uuid::from_u128(0x7661_756c_742d_6675_7a7a_2d76_6175_6c74);
pub const ATTACHMENT_ID: Uuid = Uuid::from_u128(0x6174_7461_6368_6d65_6e74_2d66_757a_7a00);
const KEY: [u8; 32] = [0x42; 32];

/// The reference a `blob_len`-byte blob would have if every chunk but the last were full:
/// `n = max(1, ceil(blob_len / (CHUNK_SIZE + 16)))` chunks, `size = blob_len - 16 n`
/// (saturating), fixed id, key and per-chunk nonces (`i` big-endian in the first 8 bytes).
pub fn fixed_ref(blob_len: usize) -> AttachmentRef {
    let n = blob_len.div_ceil(CHUNK_SIZE + TAG_LEN).max(1);
    let mut r = new_ref("fuzz.bin", 0, 0).expect("size 0 is under the cap");
    r.id = ATTACHMENT_ID;
    *r.key = KEY;
    r.size = blob_len.saturating_sub(TAG_LEN * n) as u64;
    r.chunk_nonces = (0..n as u64)
        .map(|i| {
            let mut nonce = [0u8; 24];
            nonce[..8].copy_from_slice(&i.to_be_bytes());
            nonce
        })
        .collect();
    r
}
