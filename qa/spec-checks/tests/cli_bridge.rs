//! Decodes files written by the CLI binary with the independent decoder (01 §2 header fields).
use spec_checks::*;
use std::process::Command;

fn vault_bin() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/vault")
}

/// 01 §2 "created_at: u64 unix seconds" on the header and on each slot; 00 "Explicitly accepted
/// leaks: ... vault creation time" implies a real value is stored.
#[test]
fn b01_cli_init_header_created_at() {
    let d = tempdir();
    let p = d.path().join("c.vault");
    let st = Command::new(vault_bin())
        .args(["--vault", p.to_str().unwrap(), "--password-env", "QA_MPW", "init", "--kdf-test-params"])
        .env("QA_MPW", "tidy-Walrus-orbit-Velvet-42")
        .output()
        .unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let b = std::fs::read(p.join("vault.bin")).unwrap();
    let raw = split(&b);
    let ca = u64_of(get(&raw.header, "created_at").unwrap());
    let slot_ca: Vec<u64> = get(&raw.header, "slots").unwrap().as_array().unwrap().iter().map(|s| u64_of(get(s, "created_at").unwrap())).collect();
    assert!(ca > 1_600_000_000 && slot_ca.iter().all(|c| *c > 1_600_000_000), "header created_at={ca}, slot created_at={slot_ca:?}");
    // the independent decoder opens a CLI-made vault (spec AADs, HKDF labels, NFC)
    indep::open_file(&b, "tidy-Walrus-orbit-Velvet-42");
}
