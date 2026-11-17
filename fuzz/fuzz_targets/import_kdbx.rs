//! `import_kdbx` with the password of `keepass-v4.kdbx`, so seed mutants that keep a valid
//! header and HMAC get past key verification into the XML mapping.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::{SecretString, Uuid, import_kdbx};

fuzz_target!(|data: &[u8]| {
    let password = SecretString::new("kdbx-password".to_owned());
    let _ = import_kdbx(data, &password, None, Uuid::nil(), 1_700_000_000_000);
});
