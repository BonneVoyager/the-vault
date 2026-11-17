//! The decrypted item payload decoder (`format::decode_item_plain`, public) and the manifest
//! decoder, fed directly. Byte 0 picks the format version (odd = 1, even = 2: v1 derives
//! missing field ids, v2 requires them); the rest is the plaintext CBOR.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::Uuid;
use vault_core::format::{decode_item_plain, decode_manifest, encode_item_plain};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, plain)) = data.split_first() else {
        return;
    };
    let version = if selector & 1 == 1 { 1 } else { 2 };
    let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    if let Ok(item) = decode_item_plain(plain, id, 1_700_000_000_000, version) {
        let _ = encode_item_plain(&item);
    }
    let _ = decode_manifest(plain);
});
