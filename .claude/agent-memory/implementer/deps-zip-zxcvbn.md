---
name: deps-zip-zxcvbn
description: zip 9.x migration gotchas (EOCD precheck window, declared-size enforcement, extra deps) and zxcvbn strength_bits quirks (64-bit ceiling, clock reads, cost)
metadata:
  type: project
---

zip bumped 2.6.1 -> 9.6.1 on 2026-11-17 (six RUSTSEC advisories). Declared in vault-core
(dep + dev-dep), vault-app dev-dep, qa/spec-checks, and fuzz/Cargo.toml (separate workspace;
build there with `cargo +nightly`).

- `ZipWriter::set_comment` now returns Result (warning `unused Result`, not an error).
- `import.rs::check_zip_entry_count` must mirror zip's EOCD search window. zip 9:
  `file_len - (22 + 4 + 65536)` (`ZipArchive::get_metadata`); 2.6.1 searched the whole file.
  Re-check `EOCD_SEARCH_WINDOW` on every zip bump.
- The ZIP64 refusal must mirror zip's `may_be_zip64()` (format/blocks.rs): count == u16::MAX,
  cd_size (EOCD 12..16) == u32::MAX, or cd_offset (16..20) == u32::MAX. Missing the size
  marker let a ZIP64 record bypass the 10k-entry cap (security review 2026-11-17).
- zip 9's Crc32Reader stops one byte past the *declared* uncompressed size and errors, so a
  lying-small entry surfaces as `Malformed("cannot read export.data")`, not the importer's
  `TooLarge("inflates past")` backstop (onepux.rs test updated accordingly).
- zip 9 unconditionally pulls nix (fs), libc, getrandom 0.4, typed-path into vault-core.

zxcvbn 3.1.1 backs `generator::strength_bits` (owner decision 2026-11-17):
- guesses are a saturating u64, so bits top out at exactly 64.0; the UI "Strong" bucket (>=80)
  is unreachable unless buckets are rescaled.
- Reads the clock (REFERENCE_YEAR via time::OffsetDateTime::now_utc, Instant::now); no
  feature disables it on native. default-features=false only drops derive_builder.
- Cost ~0.15-0.5 ms per typical value, ~10 ms for 100 random chars; input capped at 100 chars.
  vault-app `audit::audit` runs it per password field on the UI thread in `vault_changed`.
- Empty input returns guesses_log10 = -inf; strength_bits special-cases "" -> 0.0.

**Why:** these broke tests or silently weakened a security precheck during the bump.
**How to apply:** on any zip/zxcvbn version change, re-verify the window constant, the
lying-size test, and the 64-bit ceiling assumptions in UI thresholds.
