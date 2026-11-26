---
name: import-bounds-decisions
description: 2026-11-06 M2 (core half): 1PUX export.data bounded from the zip central directory before inflation, ImportError::TooLarge variant, what stays Malformed, test technique for forged declared sizes
metadata:
  type: project
---

1PUX import bound (bug hunt 2026-11-06 M2, core half). The archive as a whole is NOT bounded
in core (real exports carry document attachments under `files/`, never opened); the only bound
is `export.data` at `MAX_EXPORT_DATA` = 64 MiB.

- `import_1pux`: `index_for_name("export.data")` -> `by_index_raw(idx).size()` (uncompressed
  size as the central directory declares it, no decompressor built) -> refuse `> 64 MiB` with
  `ImportError::TooLarge("export.data is larger than 64 MiB")` before any inflation -> then
  `by_index(idx)` + the existing `take(MAX + 1)` backstop, which now returns
  `TooLarge("export.data inflates past 64 MiB")` (was `Malformed("export.data too large")`).
  Both bounds stay: the declared size can lie small (zip bomb) or large (forged).
- New variant `ImportError::TooLarge(String)`, `#[error("import too large: {0}")]`; payload
  names the bound only. No exhaustive matches on `ImportError` outside core (vault-app only
  constructs `Malformed`), so adding a variant was workspace-safe. KDBX's 100 MiB / 1 MiB caps
  were left as `Malformed("KeePass input exceeds the size limit")` to keep scope; owner may
  want them on `TooLarge` too (open question 2026-11-06).
- **Entry-count cap (security review 2026-11-06):** `check_zip_entry_count` runs before
  `ZipArchive::new` (which materialises one record per declared entry; app reads 1PUX up to
  1 GiB). Parses the EOCD itself: scan backwards over the last `EOCD_SEARCH_WINDOW` bytes for
  `PK\x05\x06` (**L-14, 2026-11-26:** zip 9.6.1 searches `size_of::<Zip32CentralDirectoryEnd>()`
  = 32 in-memory bytes incl. a boxed comment, NOT the 22-byte record, + 4 + 65536 = 65_572;
  the old 22+4+65536 = 65_562 left a 10-byte gap: real record with a 65_535 comment + 13
  junk bytes and a decoy EOCD inside the comment -> guard saw only the decoy, zip fell back
  to the real one. Now `ZIP_EOCD_SEARCH_WINDOW = 65_572` (static-asserted) + 1 KiB margin,
  AND `check_opened_entry_count(zip.len())` after `ZipArchive::new`, same cap, message
  "1PUX archive holds more than 10000 entries". Test
  `eocd_hidden_in_the_gap_behind_a_decoy_comment_is_still_counted`: 10_001 stored entries +
  `set_raw_comment` (writer caps at u16::MAX) + 13 appended bytes; the decoy's comment_len
  makes it end exactly at EOF so it "fits"), check EVERY candidate whose comment fits in the file (a fake record appended
  behind the real one cannot hide the count), bound `max(entries on this disk, total)` at
  `MAX_ZIP_ENTRIES` = 10_000 (zip 2.6.1 reads the zip32 count from the on-this-disk field),
  refuse either ZIP64 marker (`u16::MAX` entries or `u32::MAX` CD offset) outright, no
  plausible record in the window -> `Malformed("not a valid zip archive")` (zip would scan
  through trailing junk; stricter on purpose). Messages fixed: `TooLarge("1PUX archive
  declares more than 10000 entries")`, `TooLarge("1PUX archive declares a ZIP64 central
  directory")`. Test patches the EOCD fields at +8/+10/+16 (`eocd()`, `with_declared_entries`).
- The app (`vault-app/src/state/transfer.rs` `import_1pux_from`) still slurps through a 64 MiB
  whole-file cap; the app side was to raise that separately so core's check becomes the only bound.
- Test technique (tests/onepux.rs): `central_dir_entry(zip, name)` finds the `PK\x01\x02`
  header whose name matches, `with_declared_size(zip, name, u32)` patches offset +24
  (uncompressed size). A tiny valid `export.data` with a forged 64 MiB + 1 declared size is
  refused with `TooLarge` even though inflating it would have imported fine (proves the
  pre-inflation check); a forged *small* size on a real 64 MiB + 16 entry still trips the
  inflate backstop; exactly 64 MiB declared is accepted (`>`). zip 2.6.1 does not cross-check
  central-directory sizes against the local header or the inflated length on read.

**Why:** the hunt showed a 70 MiB 1PUX (small JSON + big `files/`) imports in core but was
refused by the app's whole-file cap; the lead wanted the entry bounded from the central
directory so the archive cap can go.
**How to apply:** keep `MAX_EXPORT_DATA` as the single 1PUX bound; any new importer size
refusal should use `TooLarge`, not `Malformed`.
