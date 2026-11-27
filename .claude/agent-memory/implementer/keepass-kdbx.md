---
name: keepass-kdbx
description: keepass-rs 0.17.0 internals relevant to bounding KDBX import (no inflate hook, nested Meta/Binaries gzip bomb, why an input-size cap cannot fix M-05), plus how to craft KDBX bombs for probes
metadata:
  type: project
---

keepass 0.17.0 (latest in the local index as of 2026-11-26) has no way for vault-core to cap
decompression: `format`, `crypt`, `compression` and `config::get_compression` are pub(crate);
no features/options touch it. Public entry points are only `Database::{open,parse,get_xml,
get_version}`; `get_xml` also inflates unbounded. No public "parse plain XML" API, so
"decrypt ourselves, inflate capped, hand XML back" is impossible without re-implementing KDBX.

Two unbounded inflates: payload (kdbx3.rs:304, kdbx4/parse.rs:120) and every
`<Meta><Binaries><Binary Compressed="True">` (xml_db/meta.rs:230), for KDBX3 *and* KDBX4.
Gzip-of-gzip nests: measured 2026-11-26 (release, `/usr/bin/time -l`):
- KDBX4 single-layer 66 KB -> 374 MB peak; 522 KB -> 2.76 GB; 2.09 MB -> 8.6 GB.
- KDBX3 nested, gzip outer: 3.2 KB -> 576 MB; 10.5 KB -> 2.2 GB (~200,000x).
- KDBX3 nested, plain outer: 697 KB -> 578 MB; 2.78 MB -> 2.2 GB.
So lowering the 100 MiB input cap cannot bound peak under 1 GiB (would need ~5 KB).
Owner decision on M-05 pending: needs a vendored/patched keepass via `[patch.crates-io]`
(root Cargo.toml, outside vault-core) or an upstream limit API.

Crafting bombs: KDBX3 header is unauthenticated and the inner stream key is in the outer
header, so a whole KDBX3 can be hand-built with aes 0.8.4 + cbc 0.1.2 + sha2 0.10 (AES-KDF
1 round, AES-256-CBC Pkcs7, hashed blocks). KDBX4 single-layer: keepass `save` with
`CompressionConfig::GZip` and a huge Notes. tests/kdbx.rs already forges KDBX4 HMAC blocks
via ChaCha20 XOR (no-compression only; inner header random key is unknown).

**Why:** spent the M-05 session proving options (a)-(c) unavailable; don't redo it.
**How to apply:** for any KDBX resource bound, start from the patch route; re-check pub API
and the index on a keepass bump.
