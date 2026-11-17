//! `import_1pux` on raw archive bytes (zip container + `export.data` JSON).
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::{Uuid, import_1pux};

fuzz_target!(|data: &[u8]| {
    let _ = import_1pux(data, Uuid::nil(), 1_700_000_000_000);
});
