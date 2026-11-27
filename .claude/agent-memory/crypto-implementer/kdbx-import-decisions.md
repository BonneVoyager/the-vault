---
name: kdbx-import-decisions
description: KDBX importer hardening (2026-10-30) — pre-parse outer-header walk mirroring keepass-rs 0.17.0, KDF limits, error mapping (classify_open_error 2026-11-06), history value-dedup, native TOTP field mapping, vendored keepass with a 256 MiB inflate cap (M-05, 2026-11-27)
metadata:
  type: project
---

`import_kdbx` walks the unauthenticated outer header itself before `Database::parse`
(keepass-rs runs the KDF before any key check; rust-argon2 aborts on alloc failure).

- Walk mirrors keepass-rs 0.17.0 exactly: `format/mod.rs` 56-89 (magic/sig/major),
  `format/kdbx3.rs` 46-118 (TLV `type u8, len u16`), `format/kdbx4/parse.rs` 163-224
  (`type u8, len u32`), `format/variant_dictionary.rs` 51-117 (`while pos + 9 < len`,
  later duplicate keys win), `config.rs` 403-462 (`$UUID`, `M`/`I`/`P`, `R`).
- Limits: AES rounds (KDBX3 TLV 6, KDBX4 `R`) <= 2^26; Argon2 `M` <= 1 GiB (bytes as
  stored), `I` <= 64, `P` <= 16. Unknown KDF UUID -> error. Also rejects fixed-width
  entries shorter than keepass-rs's panicking `byteorder` reads (TLV 3/10 < 4, TLV 6 < 8,
  dictionary u32/u64/i32/i64 short values).
- `ImportError` has NO `Unsupported` variant, so limit/unknown-KDF rejections use
  `Malformed("KDF parameters exceed safe limits")` / `Malformed("unsupported KeePass key
  derivation function")`. The 100 MiB database / 1 MiB key-file caps are still
  `Malformed("KeePass input exceeds the size limit")` (not switched to `TooLarge`, see
  [[import-bounds-decisions]]).
- KDBX4 fixture `keepass-v4.kdbx` is AES-KDF (`R`), not Argon2; Argon2 limit tests
  build a database in-test and recompute the header SHA-256 after patching.
- History: newest-first by stamp, dedup by value, drop the current password, cap
  `HISTORY_CAP` (10).
- Native TOTP: `TimeOtp-Secret-Base32` (+`-Length`/`-Period`/`-Algorithm`) and KeeTrayTOTP
  `TOTP Seed` + `TOTP Settings` become one `totp` field; raw fields stay on parse failure.
  `otp` (KeePassXC) maps separately; a clash yields `totp (2)`.

**Inner-header panic (2026-11-06, external review finding [8]):** keepass-rs 0.17.0 panics on a
KDBX4 inner-header `random-stream-id` < 4 bytes (inside the authenticated payload, cannot be
pre-validated). `Database::parse` runs inside `catch_unwind(AssertUnwindSafe(..))`; a panic maps
to `ImportError::KdbxMalformed` (fixed message). Relies on `panic = "unwind"` (root
`[profile.dist]` inherits release, sets no `panic`). Test
`crafted_kdbx4_inner_header_panic_is_caught_not_propagated` reproduces the HMAC key with
RustCrypto argon2 + manual HMAC-SHA256.

**Error classification (2026-11-06, bug hunt L2):** `classify_open_error(DatabaseOpenError)`:
`Key(_) | Cryptography(_)` -> `KdbxCredentials` (header HMAC in KDBX4 and stream-start bytes in
KDBX3 both surface as `DatabaseKeyError::IncorrectKey`; AES-CBC padding error with a wrong key
in KDBX3 is `Cryptography`). `Format(Kdbx4(BlockStream(_))) | Format(Kdbx3(BlockHashMismatch(_)))`
-> `KdbxMalformed` (owner decision 2026-11-06: keepass-rs reaches those only after the key
passed, so they mean damage with correct credentials; KDBX3's corrupted final AES-CBC block is
a `Cryptography` padding error and stays Credentials by construction). Everything else (`Io`,
`UnexpectedEof`, `VersionParse`, `UnsupportedVersion`, other `Format` incl. XML / inner header /
outer header / header hash) -> `KdbxMalformed`. `DatabaseOpenError` is `#[non_exhaustive]`;
the wildcard arm defaults to `KdbxMalformed`. keepass-rs's XML layer (xml-rs) caps nesting at
128: a valid 150-deep group tree is `Format(Kdbx4(Xml(TooDeeplyNested(128))))`; test
`rejected_content_after_a_correct_password_is_malformed_not_credentials` builds depth 150 on a
64 MiB thread and imports on an 8 MiB thread (debug frames overflow 2 MiB around depth 200).
The importer's group walk is iterative and prepends the template tag ("login") before the
group-path tag.

**Vendored keepass + inflate cap (2026-11-27, security review M-05):** keepass 0.17.0 lives in
`vendor/keepass` (registry copy minus `.cargo_vcs_info.json`/`.cargo-ok`/`Cargo.toml.orig`; its
`Cargo.lock` kept), wired by `[patch.crates-io] keepass = { path = ... }` in the root,
`fuzz/` and `qa/spec-checks/` manifests, and `exclude`d from the root workspace so
`cargo test --manifest-path vendor/keepass/Cargo.toml --features save_kdbx4` runs standalone
(its `test_xml` always fails: the tarball ships no `tests/resources`). The patch is only
`src/compression.rs` + a `lib.rs` re-export: `decompress` -> `decompress_bounded(buf, limit)`
via `Read::take(limit + 1)`, `pub const MAX_DECOMPRESSED_SIZE = 256 MiB` (inclusive), error =
`io::Error::new(InvalidData, DECOMPRESSED_SIZE_EXCEEDED)`. Detection = `is_inflate_cap(&io)`: kind
`InvalidData` AND `to_string() == keepass::DECOMPRESSED_SIZE_EXCEEDED` (flate2 1.1.x reports
corrupt streams as `InvalidInput`/`UnexpectedEof` with fixed literal messages; those stay
`KdbxMalformed`). The error arrives on TWO paths: body inflate = `DatabaseOpenError::Io`;
compressed attachment = `Format(Kdbx3|Kdbx4(Xml(ParseXmlError::Unprotect(UnprotectError::Io))))`
(review follow-up 2026-11-27) — the patch also re-exports `UnprotectError` from
`keepass::error` (`format` is `pub(crate)`) so vault-core can name that variant. Residual,
documented in 02 only: the cap is per stream, not per database (many attachments x 256 MiB). The cap
maps to `ImportError::TooLarge("KeePass database content exceeds 256 MiB when decompressed")`
(the 100 MiB input cap stays `Malformed`). vault-core tests only the classification arm (a
real over-cap file would inflate 256 MiB in the test). Upstream style: rustfmt max_width 120;
the crate denies `clippy::unwrap_used` so test modules carry `#[allow(clippy::unwrap_used)]`;
its `-D warnings` clippy fails on pre-existing lints elsewhere. Drop the vendor dir and the
three patch entries when upstream ships an equivalent fix (VAULT-PATCH.md).

**Why:** security review of the importer (2026-10-30; findings [8]/[9] 2026-11-06) and bug hunt
2026-11-06 L2 (05 §2.5 keeps the prompt open on `KdbxCredentials`, so damaged content must not
be reported as a wrong password).
**How to apply:** keep the walk byte-compatible with the pinned keepass-rs version; if the
dependency is bumped, re-read those source lines and the `DatabaseOpenError` enum before
trusting the limits or the classification.
