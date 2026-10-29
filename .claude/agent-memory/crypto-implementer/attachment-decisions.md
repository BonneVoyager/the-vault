---
name: attachment-decisions
description: Settled vault-core v1.1 attachment decisions (2026-10-29) — AttachmentRef shape, chunk AAD layout, seal-by-value, validate_ref on every write path, removal tombstones + merge rule, fixture v1-attach layout
metadata:
  type: project
---

Decisions settled while adding attachments (01 §4 "Attachments (v1.1)") to `crates/vault-core`
on 2026-10-29. Supersedes the "attachments: never parsed, kept in extras" line in
[[format-decisions]]. See also [[mutation-merge-decisions]].

**Model:** `item::AttachmentRef { id, name, size, key: Zeroizing<[u8;32]>, chunk_nonces:
Vec<[u8;24]>, added_at, extras }`, `Item.attachments: Vec<AttachmentRef>` (always written,
`[]` when empty; missing/null key tolerated on read). Debug prints `[REDACTED]` for key and
only the nonce count. `Item::attachment(id)` lookup. No FORMAT_VERSION bump (spec says so).

**Chunk AAD (byte-exact, BE):** `vault_id(16) || ref.id(16) || index u32(4) || chunk_count
u32(4) || attachment_version u16(2)` = 42 bytes, builder `format::attachment_chunk_aad(
attachment_version, vault_id, attachment_id, index, count)`. The version is the CONSTANT
`attachment::ATTACHMENT_VERSION = 1` (blob-layout version), NOT the file's format_version
(lead decision 2026-10-29: a FORMAT_VERSION bump must not invalidate immutable blobs). The
builder keeps the version parameter only so tests can craft a foreign-version blob; `seal`
and `open` take no version argument and pass the constant. For v1 files both values are 1,
so blobs sealed under the earlier rule are byte-identical (v1-attach fixture untouched).
`chunk_count` = `chunk_nonces.len()`. Bump ATTACHMENT_VERSION only if the chunk layout or
AAD changes (requires re-sealing every blob).

**`attachment` module:** `CHUNK_SIZE = 1_048_576`, `MAX_ATTACHMENT_SIZE = 100_000_000`,
`chunk_count(size) = max(1, ceil(size/CHUNK))` (u64), `blob_file_name(id) = id.as_simple() +
".bin"`, `new_ref(name, size, now)` (random id/key/nonces; TooLarge over cap),
`validate_ref(&ref)` (cap + nonce-count invariant; shared by parser, seal and vault writes),
`seal(vault_id, ref BY VALUE, Read, Write) -> (ref, u64 bytes written)` — review
2026-10-29: consuming the ref enforces "one ref, one seal" so a retry cannot reuse key+nonce
pairs; a retry needs a new `new_ref`. `open(vault_id, &ref, Read, Write) -> ()`. Per-attachment random key
is used; `Keys.attach_key` stays derived-but-unused.
- `seal`: ref must be self-consistent (`InvalidRef`), input must be exactly `size` bytes
  (`SizeMismatch{expected, actual}`; actual = expected+1 when too long, detected by a 1-byte
  probe). Flushes `out` on success.
- `open`: trusts only the ref: reads `n = chunk_nonces.len()` chunks of CHUNK+16 (last one
  may be shorter, min 16), rejects trailing bytes after a full last chunk via a 1-byte probe
  BEFORE decrypting it, verifies every tag, then requires total plaintext == `size`. Every
  blob-vs-ref disagreement (flip, swap, drop, append, other vault/version/id, one nonce
  fewer/more, size edited) = `Tampered`. `n == 0` = `InvalidRef`. **Output is partial on Err**
  (earlier chunks already written); callers must discard. Chunk buffers are `Zeroizing`.
- Error enum `AttachmentError { TooLarge, SizeMismatch, InvalidRef(&'static str), Tampered,
  Io(io::Error) }` — separate from `VaultError`, not Clone/PartialEq (io::Error).

**Parser strictness (stricter reading):** `attachment_from_value` rejects `size > cap` and
`chunk_nonces.len() != chunk_count(size)` as `Malformed`; key read via `as_key` which wipes
the intermediate Vec. An `attachments` entry in `Item.extras` is dropped by `build_map` on
write (known-key collision) — roundtrip test updated accordingly.

**Vault API:** `add_attachment_ref(item, ref, now)` (duplicate id -> Malformed("duplicate
attachment .."), invalid ref -> Malformed("attachment <id>: ..")), `remove_attachment_ref(item,
id, now)` (unknown -> Malformed("unknown attachment ..")), both restamp via `stamp`/`restamp`
like other mutations and work on tombstones; `attachment_ids()` iterates all items incl.
tombstones (orphan GC input). **Every write path validates refs** (review 2026-10-29: an
invalid ref written now bricks the vault at next unlock because the parser is strict):
`update` validates after `f` and restores the pre-call clone on error; `insert` keeps its
infallible `-> Uuid` signature (10 downstream call sites) and PANICS on an invalid ref, with
`try_insert -> Result<Uuid, VaultError>` as the fallible twin. If the lead ever wants `insert`
itself fallible, flip cli/app/sync callers to `try_insert` first.

**Removal tombstones (lead request 2026-10-29, after vault-sync found union-by-id resurrects
a removed ref whose blob was pruned):** `AttachmentTombstone { id, removed_at }` (Copy, Debug,
PartialEq), `Item.removed_attachments`, CBOR `"removed_attachments": [{ "id": bytes(16),
"removed_at": u64 }]` — OPTIONAL key, written only when non-empty (so v1 bytes/fixtures are
unchanged; missing/null = empty; entries have no extras slot, unknown keys dropped like
HistoryEntry). `remove_attachment_ref` moves the ref to a marker with `removed_at` = the item's
new stamp, LIFTED to at least the removed ref's `added_at` (`stamp(now, modified_at).max(
added_at)`; the item restamps to that floor) so an ahead-clock add cannot outrun its marker;
`add_attachment_ref` clamps `r.added_at` to <= the item's new stamp. `check_attachment_refs`
(insert/try_insert/update) also rejects a ref whose id has a marker on the same item. `merge::normalize_attachment_tombstones`: newest first, ties by id, one per id (max
removed_at), cap `vault::ATTACHMENT_TOMBSTONE_CAP = 64`; applied in remove, try_insert,
update and merge. **Merge (live+live):** union both marker lists, then union refs by id MINUS
any ref with a marker `removed_at >= added_at`, sorted `(added_at, id)`; item-tombstone cases
still clone wholesale. `add_attachment_ref` refuses an id that has a marker (Malformed
"duplicate attachment"). `purge_tombstones_older_than(cutoff)` also drops markers with
`removed_at < cutoff` on every item (no restamp; return value counts items only).
`attachment_ids()` lists LIVE refs only (tombstoned ids are prunable). `item_eq` compares
attachments (incl. key bytes) and markers.

**Fixture:** `tests/fixtures/v1-attach.vault` (item id 0x06.., refs 0x0A.. empty.txt 0 B and
0x0B.. three-chunks.bin 2 MiB+7, content `i % 251`), blobs under
`v1-attach.vault.attachments/<hex>.bin` (~2 MB committed). Regenerated by ignored
`regenerate_attach_fixture`; read via `std::fs` at test time (not include_bytes).

**Why:** points where 01 §4 / lead brief were silent; changing them changes blob bytes or
error mapping in vault-sync.
**How to apply:** vault-sync should write blobs to a temp path and rename on `Ok`, delete on
`Err`; never derive chunk layout from the blob length; keep the AAD builder in `format`.
