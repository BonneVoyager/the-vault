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

**Why:** security review of the importer (lead message 2026-10-30).
**How to apply:** keep the walk byte-compatible with the pinned keepass-rs version; if
the dependency is bumped, re-read those source lines before trusting the limits.
