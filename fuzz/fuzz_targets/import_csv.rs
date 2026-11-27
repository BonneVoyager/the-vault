//! `import_csv` on raw bytes with the default mapping, as the app and the CLI call it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::{CsvMapping, Uuid, import_csv};

fuzz_target!(|data: &[u8]| {
    let _ = import_csv(data, &CsvMapping::default(), Uuid::nil(), 1_700_000_000_000);
});
