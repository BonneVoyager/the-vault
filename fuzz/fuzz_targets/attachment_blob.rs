//! `attachment::open` on arbitrary blob bytes under a fixed reference (fixed vault id,
//! attachment id, key and nonces; `size` and the chunk count derived from the blob length, see
//! `common/attachment.rs`). The committed seed is a blob sealed under that reference, so
//! length-preserving mutants reach the tag check and the seed itself the full success path.
#![no_main]

#[path = "common/attachment.rs"]
mod fixed;

use libfuzzer_sys::fuzz_target;
use vault_core::attachment::open;

fuzz_target!(|data: &[u8]| {
    let r = fixed::fixed_ref(data.len());
    let mut out = Vec::new();
    let _ = open(fixed::VAULT_ID, &r, data, &mut out);
});
