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

## Seed, then run

The corpus is gitignored and rebuilt from the committed fixtures (`crates/vault-core/tests/fixtures`)
by `seed.sh`: vault and kdbx fixtures are copied, and `src/bin/seed.rs` decrypts the vaults into
`inner_payload` seeds and builds sample archives for `import_1pux`. Seed first:

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
```

New interesting inputs land in `corpus/<target>/`, which is local only and never committed (it is
gitignored, and the seeds hold decrypted fixture plaintext). After a long run, shrink it:

```
cargo +nightly fuzz cmin <target>
```

then copy the named seeds back (`cmin` renames everything to content hashes):
`crates/vault-core/tests/fixtures/*.vault` into `corpus/vault_parse/`, `*.kdbx` into
`corpus/import_kdbx/`. The `inner_payload` and `import_1pux` seeds were generated once from the
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
