# Vendored keepass 0.17.0 with a capped gzip inflate

Local copy of the `keepass` crate, wired in through `[patch.crates-io]` in the root
`Cargo.toml`, `fuzz/Cargo.toml` and `qa/spec-checks/Cargo.toml`. Drop the directory and the
three patch entries once upstream ships an equivalent fix.

- Upstream: https://github.com/sseemayer/keepass-rs
- Base: crates.io `keepass-0.17.0` (MIT), tarball SHA-256
  `8025344cf174f72cccbac2a99640a8d1e82cf46922d57e06a45a32e49edfed16` (the `checksum` line the
  patch removed from the lockfiles; `shasum -a 256 keepass-0.17.0.crate`), published from commit
  `26cb076aa5cbbe36e175326dfdaf5a19799c4085` (the registry's `.cargo_vcs_info.json` marks that
  tree as dirty, so the published source may differ slightly from the commit).
- Registry metadata files (`.cargo_vcs_info.json`, `.cargo-ok`, `Cargo.toml.orig`) are not
  kept. The crate's `Cargo.lock` is kept so its own test suite is reproducible
  (`cargo test --manifest-path vendor/keepass/Cargo.toml`). The published tarball ships no
  `tests/` directory, so the crate's tests that open `tests/resources/*.kdbx` fail here with
  "No such file or directory"; that is unrelated to the patch.
- Version stays `0.17.0` so the patch satisfies the `^0.17.0` requirements.

## Reason

Security review 2026-11-26, M-05: `GZipCompression::decompress` inflated attacker-controlled
data with `read_to_end` into an unbounded buffer. All three inflate sites (KDBX3 body, KDBX4
body, each compressed attachment) go through that one function, so a sub-megabyte database
could allocate gigabytes during import.

## Files changed (the upstream PR)

Suggested title: `fix(compression): cap decompressed size to prevent memory exhaustion`.

- `src/compression.rs`: `decompress` now runs through `decompress_bounded(in_buffer, limit)`,
  which reads through `Read::take(limit + 1)` and returns
  `io::Error::new(InvalidData, DECOMPRESSED_SIZE_EXCEEDED)` when more than `limit` bytes arrive
  (exactly `limit` succeeds). Adds the documented `pub const MAX_DECOMPRESSED_SIZE` (256 MiB)
  and `pub const DECOMPRESSED_SIZE_EXCEEDED` (the error message, so callers can tell the cap
  from a corrupt stream, which flate2 also reports as `InvalidData`), plus unit tests.
- `src/lib.rs`: re-exports the two constants (`compression` is a private module).
- `src/error.rs`: adds `UnprotectError` to the `keepass::error` re-exports so a caller can match
  the cap on a compressed attachment, which surfaces as
  `Format(Kdbx3|Kdbx4(Xml(ParseXmlError::Unprotect(UnprotectError::Io(_)))))` (`format` is
  `pub(crate)`, so the type was not nameable before).
- `src/format/xml_db/entry.rs`: doc comments on `UnprotectError` and its `Base64`, `Decrypt` and
  `Io` variants (now public API under the crate's `missing_docs = warn`).

Nothing else in the crate changes; the `Compression` trait signature is untouched.
