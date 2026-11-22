//! Measurement, not a check: which phase of a save dominates (serialise + encrypt, or the
//! atomic write). `#[ignore]`d; run with
//! `cargo test -p vault-sync --release --test save_timing -- --ignored --nocapture`.
//!
//! The crate's atomic-write routine is `pub(crate)`, so the write phase is timed with the
//! equivalent std sequence: create a temp file in the same directory, `write_all`,
//! `sync_all`, `rename` (no directory fsync, which the real routine adds).

use std::fs::{self, File};
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use vault_core::{Field, FieldKind, Item, KdfParams, SecretString, Uuid};
use vault_sync::{MAX_VAULT_FILE_SIZE, NoopHooks, SyncedVault, VAULT_FILE_NAME};

const NOW: u64 = 1_700_000_000_000;
const RUNS: usize = 5;

/// Deterministic printable noise (xorshift), so the payload is not trivially compressible.
fn noise(seed: &mut u64, len: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,-";
    (0..len)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            A[(*seed % A.len() as u64) as usize] as char
        })
        .collect()
}

fn field(name: &str, kind: FieldKind, value: String) -> Field {
    Field::new(name, kind, SecretString::new(value), NOW)
}

fn login(i: usize, note_len: usize, seed: &mut u64) -> Item {
    let mut it = Item::new(format!("Example Service {i}"), Uuid::nil(), NOW);
    it.fields.push(field(
        "username",
        FieldKind::Text,
        format!("user{i}@example.com"),
    ));
    it.fields
        .push(field("password", FieldKind::Password, noise(seed, 20)));
    it.fields.push(field(
        "website",
        FieldKind::Url,
        format!("https://service{i}.example.com/login"),
    ));
    it.fields
        .push(field("notes", FieldKind::Notes, noise(seed, note_len)));
    it
}

fn best_ms(mut f: impl FnMut()) -> f64 {
    f(); // warm-up
    (0..RUNS)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .fold(f64::MAX, f64::min)
}

fn measure(label: &str, count: usize, note_len: usize) {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("t.vault");
    let mut v = SyncedVault::create(
        &pkg,
        &SecretString::new("pw".to_owned()),
        KdfParams::for_tests(),
        Uuid::from_u128(0xD0D0),
        Arc::new(NoopHooks),
    )
    .unwrap();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    v.edit(|u| {
        for i in 0..count {
            u.insert(login(i, note_len, &mut seed), NOW);
        }
    })
    .unwrap();
    v.save().unwrap();

    let bytes = v.vault().unwrap().serialize();
    assert!((bytes.len() as u64) < MAX_VAULT_FILE_SIZE);
    let ser = best_ms(|| {
        let b = v.vault().unwrap().serialize();
        std::hint::black_box(b);
    });

    let target = pkg.join(VAULT_FILE_NAME);
    let tmp = pkg.join(".timing.tmp");
    let write = best_ms(|| {
        let mut f = File::create(&tmp).unwrap();
        f.write_all(&bytes).unwrap();
        f.sync_all().unwrap();
        drop(f);
        fs::rename(&tmp, &target).unwrap();
    });

    // Full save: needs a dirty vault each run; the no-op edit sets the flag.
    let save = best_ms(|| {
        v.edit(|_| {}).unwrap();
        v.save().unwrap();
    });

    println!(
        "{label:<8} {:>12} {ser:>12.1} {write:>16.1} {save:>14.1}",
        bytes.len()
    );
}

#[test]
#[ignore = "timing measurement; run explicitly with --ignored --nocapture"]
fn save_phase_timing() {
    println!(
        "{:<8} {:>12} {:>12} {:>16} {:>14}",
        "vault", "bytes", "serialize ms", "write+fsync ms", "full save ms"
    );
    measure("V1", 500, 200);
    measure("V2", 200, 300 * 1024);
}
