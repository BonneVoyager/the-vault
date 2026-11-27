# keepass-rs: unbounded gzip inflate (advisory draft)

Status: submitted privately by the owner on 2026-11-27 (GitHub Security Advisory, severity
Medium, CVSS 5.5, CWE-409); fix branch `fix/decompression-cap` pushed to the owner's fork.
PR to open once a maintainer responds, or after about two weeks of silence.

Draft for the owner to submit through the GitHub **Security** tab of
https://github.com/sseemayer/keepass-rs ("Report a vulnerability"). Their SECURITY.md
and CONTRIBUTING.md ask for a private report first and a PR only after the maintainers
agree. Our fix lives in `vendor/keepass/` (see `vendor/keepass/VAULT-PATCH.md`); the
crate diff there is the PR.

---

## Title

Unbounded decompression of database payload and attachments (memory exhaustion)

## Summary

`GZipCompression::decompress` (`src/compression.rs`) inflates with `read_to_end` into an
unbounded `Vec<u8>`. Every inflate in the crate goes through it:

- KDBX3 body: `src/format/kdbx3.rs` (`compression.decompress(&buf)`)
- KDBX4 body: `src/format/kdbx4/parse.rs` (`.decompress(&payload_compressed)`)
- KDBX4 compressed binaries: `src/format/xml_db/meta.rs` (`Binary::xml_to_db`)

A database whose compressed payload or attachment is a deflate stream with a very high
ratio (zeros compress at roughly 1000:1) makes `Database::open` / `Database::parse`
allocate the full inflated size before any XML parsing or size check can run. A file of a
few MiB can request tens of GiB and abort the process on allocation failure, or push the
host into swap.

## Preconditions

The stream sits inside the encrypted, authenticated payload, so the victim must open the
file with the key the attacker chose. That is the ordinary "import this database, the
password is X" case for any application that lets users import a KeePass file.

## Affected versions

All released versions including 0.17.0; `master` at the time of writing is unchanged.

## Reproduction

1. Create a KDBX4 database with any key.
2. Replace the inner payload with a gzip stream of ~1 GiB of zeros (about 1 MiB
   compressed), re-encrypt and re-sign with the same key, or simpler: store a ~1 GiB
   zero-filled attachment, which the crate gzips on save.
3. Call `Database::parse` with the key under a memory limit (for example `ulimit -v`):
   the process aborts while inflating, before any parse error can be returned.

## Suggested fix

Bound the inflate with `Read::take(limit + 1)` and return
`io::Error::new(ErrorKind::InvalidData, ..)` when the extra byte arrives. The existing
`Result<Vec<u8>, io::Error>` signature stays, so all three call sites are covered without
API changes. A documented `pub const` default limit is enough for a first fix; a
configurable option on `Database::parse` can follow.

Patch: `src/compression.rs` (bounded inflate behind `decompress_bounded`, two public
constants `MAX_DECOMPRESSED_SIZE` = 256 MiB and `DECOMPRESSED_SIZE_EXCEEDED` so callers can
tell the cap from a corrupt stream, four unit tests), one re-export line in `src/lib.rs`, a
`pub use` of `UnprotectError` in `src/error.rs` with doc lines on its variants in
`src/format/xml_db/entry.rs` so callers can match the attachment path.
Commit title: `fix(compression): cap decompressed size to prevent memory exhaustion`.

## Credit

Found by an automated security review of a downstream application (2026-11-26); fix by the
downstream maintainers.
