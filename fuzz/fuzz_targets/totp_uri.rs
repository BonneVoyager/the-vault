//! `Totp::parse_uri` on arbitrary UTF-8, then one code at a fixed timestamp when it parses.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::Totp;

fuzz_target!(|data: &[u8]| {
    let Ok(uri) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(totp) = Totp::parse_uri(uri) {
        let _ = totp.code(1_700_000_000);
    }
});
