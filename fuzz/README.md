# vault-core fuzzing

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of the vault-core parsers that read
attacker-controlled bytes. This directory is its own Cargo workspace; it is not a member of the
main workspace, and the stable pin in `rust-toolchain.toml` is untouched. Always use
`cargo +nightly fuzz ...` (the `+nightly` overrides the pin for that command only).

## Install

```
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked
```

(`cargo install` under the default stable toolchain may be too old for cargo-fuzz's deps.)

## Targets

| target          | entry point                                                             |
|-----------------|-------------------------------------------------------------------------|
| `vault_parse`   | `LockedVault::parse`, header accessors, `unlock_with_kek` (all-zero KEK), `unlock_with_key` with the real key of `v2-basic.vault` |
| `inner_payload` | `format::decode_item_plain` (byte 0: odd = format v1, even = v2) and `format::decode_manifest` |
| `import_kdbx`   | `import_kdbx(bytes, "kdbx-password", no keyfile)`                       |
| `import_1pux`   | `import_1pux(bytes)` on the raw zip                                     |
| `import_csv`    | `import_csv(bytes, CsvMapping::default())`, as the app and CLI call it  |
| `totp_uri`      | `Totp::parse_uri` on UTF-8 input, then `code(1_700_000_000)` when it parses |
| `attachment_blob` | `attachment::open` under a fixed reference (`fuzz_targets/common/attachment.rs`: fixed vault id, attachment id, key, nonces; size from the blob length) |
| `export_csv_roundtrip` | items built from the input, `export_csv`, then `import_csv`, which must succeed with one item per live item (replaces an `item_decode` target: `inner_payload` already covers the item decoder) |

Not fuzzed: QR decoding in `vault-macos`. It needs ImageIO on the main thread and a GUI
session, which a libFuzzer process does not have.

## Seed, then run

The corpus is gitignored and rebuilt by `seed.sh` from the committed fixtures
(`crates/vault-core/tests/fixtures`) and the committed `seeds/` folder: vault and kdbx fixtures are
copied, and `src/bin/seed.rs` decrypts the vaults into `inner_payload` seeds and builds sample
archives for `import_1pux`.

`seeds/<target>/` holds the committed seeds of `import_csv` (a three-row CSV, stored as `.txt`
because the root `.gitignore` excludes `*.csv`), `totp_uri` (two otpauth URIs, one with
`period=60`), `attachment_blob` (one blob sealed under the fixed reference) and
`export_csv_roundtrip` (one minimal login item, three mixed items). `src/bin/seed.rs` regenerates
them byte-identically on every run (no diff when nothing changed), and `seed.sh` copies them into
the gitignored `corpus/<target>/`. Seed first:

```
./fuzz/seed.sh
```

Then run, from inside `fuzz/` or with `--fuzz-dir fuzz`:

```
cd fuzz
RUST_BACKTRACE=1 cargo +nightly fuzz run vault_parse   -- -max_len=65536 -max_total_time=90
RUST_BACKTRACE=1 cargo +nightly fuzz run inner_payload -- -max_len=65536 -max_total_time=90
RUST_BACKTRACE=1 cargo +nightly fuzz run import_kdbx   -- -max_total_time=120
RUST_BACKTRACE=1 cargo +nightly fuzz run import_1pux   -- -max_total_time=120
RUST_BACKTRACE=1 cargo +nightly fuzz run import_csv            -- -max_total_time=120
RUST_BACKTRACE=1 cargo +nightly fuzz run totp_uri              -- -max_total_time=120
RUST_BACKTRACE=1 cargo +nightly fuzz run attachment_blob       -- -max_total_time=120
RUST_BACKTRACE=1 cargo +nightly fuzz run export_csv_roundtrip  -- -max_total_time=120
```

New interesting inputs land in `corpus/<target>/`, which is local only and never committed (it is
gitignored, and the fixture-derived seeds hold decrypted fixture plaintext); only `seeds/` is
committed. After a long run, shrink it:

```
cargo +nightly fuzz cmin <target>
```

then copy the named seeds back (`cmin` renames everything to content hashes):
`crates/vault-core/tests/fixtures/*.vault` into `corpus/vault_parse/`, `*.kdbx` into
`corpus/import_kdbx/`, and `seeds/<target>/*` into `corpus/<target>/` (or rerun `seed.sh`). The `inner_payload` and `import_1pux` seeds were generated once from the
fixtures (decrypted item / manifest plaintexts with a version byte prefixed) and from
`tests/onepux.rs::sample()`.

## Reproduce and minimise a crash

Crashes, timeouts and OOMs are written to `artifacts/<target>/` (gitignored).

```
RUST_BACKTRACE=1 cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>
cargo +nightly fuzz tmin <target> artifacts/<target>/crash-<hash>
```

`tmin` writes `artifacts/<target>/minimized-from-<hash>`; turn the minimised input into a
regular `cargo test -p vault-core` regression test before fixing.
