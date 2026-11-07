//! Compresses the bundled brand-icon table (`assets/brand-icons.tsv`, ~4.7 MB of SVG path
//! data) into `$OUT_DIR/brand-icons.tsv.deflate`, which `src/icon.rs` embeds and inflates
//! on the first brand lookup. The stream is zlib-wrapped deflate (RFC 1950: deflate plus an
//! Adler-32 trailer) rather than raw deflate, so a corrupt blob fails the checksum instead
//! of yielding garbage.

use std::io::Write as _;
use std::path::PathBuf;

/// Upper bound on the compressed table; a larger blob means the table grew or stopped
/// compressing well, and the size budget should be looked at again.
const MAX_COMPRESSED: usize = 5 * 1024 * 1024 / 2; // 2.5 MiB

fn main() {
    let src = "assets/brand-icons.tsv";
    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-changed=build.rs");

    let tsv = std::fs::read(src).unwrap_or_else(|e| panic!("reading {src}: {e}"));
    assert!(
        std::str::from_utf8(&tsv).is_ok(),
        "{src} is not valid UTF-8"
    );

    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&tsv).expect("compressing brand table");
    let packed = enc.finish().expect("compressing brand table");
    assert!(
        packed.len() < MAX_COMPRESSED,
        "compressed brand table is {} bytes, budget is {MAX_COMPRESSED}",
        packed.len()
    );

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR not set"))
        .join("brand-icons.tsv.deflate");
    std::fs::write(&out, &packed).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
    // Lets the decoder allocate the exact size once and check it got everything.
    println!("cargo:rustc-env=VAULT_BRAND_TSV_LEN={}", tsv.len());
}
