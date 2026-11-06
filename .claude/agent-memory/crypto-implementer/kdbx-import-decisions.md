---
name: kdbx-import-decisions
description: KDBX importer hardening (2026-10-30) — pre-parse outer-header walk mirroring keepass-rs 0.17.0, KDF limits, error mapping, history value-dedup, native TOTP field mapping
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
- `ImportError` has NO `Unsupported` variant and `import.rs` is outside the importer's
  file ownership, so limit/unknown-KDF rejections use `Malformed("KDF parameters exceed
  safe limits")` / `Malformed("unsupported KeePass key derivation function")`. Lead
  asked for `Unsupported`; flagged as a deviation on 2026-10-30.
- KDBX4 fixture `keepass-v4.kdbx` is AES-KDF (`R`), not Argon2; Argon2 limit tests
  build a database in-test and recompute the header SHA-256 after patching, otherwise
  keepass-rs's hash check (which runs before the KDF) masks the test.
- History: newest-first by stamp, dedup by value, drop the current password, cap
  `HISTORY_CAP` (10). Ties keep keepass-rs list order (stable sort; synthetic data only).
- Native TOTP: `TimeOtp-Secret-Base32` (+`TimeOtp-Length`/`-Period`/`-Algorithm`
  `HMAC-SHA-1|256|512`) and KeeTrayTOTP `TOTP Seed` + `TOTP Settings` `period;digits`
  become one `totp` field (URI built, validated via `Totp::parse_uri`, canonicalised
  with `to_uri`, label = entry title percent-encoded). On any parse failure the raw
  fields stay as custom fields. `otp` (KeePassXC) still maps separately; a clash yields
  `totp (2)`.

**Inner-header panic (2026-11-06, external review finding [8]):** keepass-rs 0.17.0 reads the
KDBX4 inner-header `random-stream-id` with a fixed-width `LittleEndian::read_u32` that panics
when the field is < 4 bytes. The inner header is inside the encrypted/HMAC-protected payload so
it CANNOT be pre-validated (documented in a comment); `check_outer_header` only covers the outer
header. Fix: `Database::parse` runs inside `std::panic::catch_unwind(AssertUnwindSafe(..))`; a
panic maps to new `ImportError::KdbxMalformed` (fixed message, no payload). Relies on
`panic = "unwind"` — root `[profile.dist]` inherits release and sets no `panic`, so it stays
unwind (comment notes this; do NOT edit Cargo.toml). vault-core calls no `std::panic::set_hook`,
so the default hook runs (prints generic slice-bounds message + location, no secret).
Test `crafted_kdbx4_inner_header_panic_is_caught_not_propagated` (tests/kdbx.rs): saves a valid
ChaCha20 + Argon2d + no-compression KDBX4, then flips ONE ciphertext byte (ChaCha20 stream XOR:
plaintext len 4 -> 0 at payload offset 1) and recomputes block-0 HMAC. HMAC key reproduced with
RustCrypto `argon2` (matches rust-argon2 output) + manual HMAC-SHA256 from `sha2` (no hmac dep).
Asserting `KdbxMalformed` (not `KdbxCredentials`) self-validates the crypto reproduction: wrong
keys would fail block-stream auth before reaching the panic. KDBX4 HMAC key =
SHA512(master_seed(TLV4) || Argon2d(SHA256(SHA256(pw)), salt S) || 0x01); block key =
SHA512(index_u64le || hmac_key); block = hmac(32)|size(u32le)|data at header_end+64.

**Why:** security review of the importer (lead message 2026-10-30; findings [8]/[9] 2026-11-06).
**How to apply:** keep the walk byte-compatible with the pinned keepass-rs version; if
the dependency is bumped, re-read those source lines before trusting the limits.
