# 01 — Vault file format & cryptography

File extension: `.vault`. Since 2026-10-30 a vault is a macOS package directory `<name>.vault/` (03 §1) whose `vault.bin` is the file described here; attachments (v1.1) live in `<name>.vault/attachments/` and backups in `<name>.vault/backups/`.

All integers big-endian. All CBOR is canonical (RFC 8949 §4.2.1) so byte-equality means content-equality.

## 1. Layout

```
offset  size   field
0       4      magic              b"RVLT"
4       2      format_version     u16, 1 or 2 (§9; new vaults are written as 2 since 2026-10-31)
6       4      header_len         u32
10      N      header             CBOR map (plaintext)
10+N    *      body               CBOR array of Record (to EOF)
```

Parsers reject: wrong magic, `format_version > SUPPORTED`, `header_len` beyond EOF, trailing bytes after the body array.

## 2. Header (plaintext CBOR map)

```
{
  "vault_id":    bytes(16)     UUIDv4, random at creation, never changes
  "created_at":  u64           unix seconds
  "kdf": {
    "alg":       "argon2id"
    "m_cost":    u32           KiB, default 65536 (64 MiB)
    "t_cost":    u32           default 3
    "p_cost":    u32           default 4
    "salt":      bytes(32)     random
  }
  "slots": [ KeySlot, ... ]   at least one
  "slots_modified_at": u64     optional (v1.1); unix millis of the last change to slots or kdf; SET AT CREATION too (so every new vault has a digest-bound header, §4); merge takes the newer header (03 §5)
  "slots_device_id": bytes(16)  optional (v1.1); device that made that change; merge tie-break (03 §5)
}
```

### KeySlot

```
{
  "id":          bytes(16)     UUIDv4
  "kind":        "password" | "enclave" | "passkey" | "recovery"
  "nonce":       bytes(24)
  "wrapped_key": bytes(48)     XChaCha20-Poly1305( vault_key ) → 32 ct + 16 tag
  "created_at":  u64
}
```

- `password` slot: KEK = `Argon2id(password_utf8_nfc, salt, m,t,p) → 32 bytes`. The password is NFC-normalised before hashing.
- `enclave` slot (phase 4): KEK is a random 32-byte key held in the Keychain, access-controlled by Touch ID. The slot itself is identical in structure.
- `passkey` slot (post-phase-5, macOS 15): extra keys `credential_id: bytes`, `prf_salt: bytes(32)` (random, static per slot), `rp_id: tstr`. KEK = `HKDF-SHA256(ikm = prf_output, salt = vault_id, info = "vault/slot/passkey/v1")` where `prf_output` is the 32-byte WebAuthn PRF result for `prf_salt` from the passkey assertion. The password slot stays; either factor unlocks. The PRF output must be identical on every device that holds the synced passkey; verify this before relying on cross-device unlock. Not yet implemented.
- `recovery` slot (v2): reserved.

AAD for unwrapping any slot: `magic || format_version || vault_id || slot.id || slot.kind`. The header's slots and `format_version` are therefore one unit: a merge adopts the format version together with the slots (03 §5; bug hunt 2026-10-31). Tampering with KDF params does not break unwrap (they're not in AAD by design — otherwise you can't rotate them); it just makes derivation produce the wrong KEK and the tag fails. Tampering with `vault_id` fails every slot. Once a file carries `slots_modified_at`, the KDF params and slots are additionally bound through the manifest's `header_digest` (§4), so tampering with them is detected via the manifest on the `unlock_with_key` path (`Tampered(Manifest)`); on the password path a KDF edit still surfaces as `WrongPassword` because the slot unwrap fails before the manifest is reached.

Multiple `password` slots are allowed in the format but v1 UI exposes one.

Slot ids must be unique within a header; a duplicate is `Malformed`. A slot whose `kind` is unknown to the reader is kept as an **opaque slot**: `id` and `kind` are read, every other entry is preserved verbatim and re-emitted in the original position, the slot is skipped at unlock, may be removed by id, and is dropped by `rotate_vault_key` like an `enclave` slot. Kind strings match exactly (case and whitespace sensitive).

## 3. Keys

```
vault_key   32 bytes, random (OsRng) at creation. Never derived, never exported.
item_key    = HKDF-SHA256(ikm=vault_key, salt=vault_id, info="vault/item/v1")
manifest_key= HKDF-SHA256(ikm=vault_key, salt=vault_id, info="vault/manifest/v1")
attach_key  = HKDF-SHA256(ikm=vault_key, salt=vault_id, info="vault/attachment/v1")   (v1.1)
```

Changing the master password: derive new KEK, re-wrap `vault_key`, replace the password slot. Items are untouched. Rotating `vault_key` itself (re-encrypt everything) is a separate explicit operation, not part of password change.

## 4. Body records

```
Record = ItemRecord | ManifestRecord
```

Exactly one `ManifestRecord` per file; it is the **last** record. Zero or more `ItemRecord`s before it.

### ItemRecord

```
{
  "t":           "item"
  "id":          bytes(16)     UUIDv4
  "modified_at": u64           unix millis of the newest field/metadata change
  "nonce":       bytes(24)
  "ct":          bytes         XChaCha20-Poly1305( CBOR(ItemPlain) )
}
```

AAD = `vault_id || item.id || modified_at_be64 || format_version_be16`.

`id` and `modified_at` are plaintext so `vault-sync` can decide whether a merge is needed without decrypting, and so the manifest check works. Everything else is inside `ct`.

### ItemPlain (encrypted payload)

```
{
  "kind":        (removed 2026-10-30: categories replaced by template tags; writers omit it, readers keep it as an unknown key)
  "title":       tstr
  "deleted_at":  u64 | null     tombstone when non-null; fields may be empty then
  "device_id":   bytes(16)      device that made the latest change
  "favorite":    bool
  "tags":        [tstr]
  "icon":        { "kind": tstr, "value": tstr, "color": tstr (optional) }   (v1.2, optional, no version bump; app-interpreted icon choice, e.g. kind "symbol" | "logo" | "image"; core validates types only; unknown keys inside the map are preserved; writers omit the key when there is no icon, readers treat missing or null as none; merge treats it as item metadata that travels with the metadata winner)
  "title_modified_at": u64, "favorite_modified_at": u64, "tags_modified_at": u64, "icon_modified_at": u64   (2026-10-31, optional, no bump: per-attribute stamps so concurrent edits of different attributes on two devices both survive (03 §5); each is set by `update` when that attribute changes, monotone like field stamps; a missing stamp reads as the item's `modified_at`, and the first mutation of an item without stamps pins each missing stamp at the item's `modified_at` before that mutation, so later edits of other parts of the item cannot make an untouched attribute look freshly edited; `item.modified_at` is the maximum of every field and attribute stamp)
  "created_at":  u64   (v1.3, optional, no version bump; unix millis the item was created; writers omit the key when unknown, readers treat missing or null as unknown and any other non-integer as Malformed; immutable metadata: a merge keeps the minimum of the two known values, or whichever side has one, and a differing created_at alone is not a change and never bumps modified_at)
  "fields":      [Field]
  "attachments": [AttachmentRef]   (v1.1, empty in v1)
  "removed_attachments": [{ "id": bytes(16), "removed_at": u64 }]   (v1.1, optional; tombstones so a removal survives merge, capped at 64 only during a merge and only for markers neither side still references, see 03 §5; purged with item tombstones)
  "history":     [HistoryEntry]    last 10 password values, optional
  "removed_history": [u64]         optional; `replaced_at` stamps of history entries the user deleted (never the value), cap 10 newest, purged with item tombstones
  "removed_fields": [{ "id": bytes(16), "removed_at": u64 }]   (version 2, optional; field removal tombstones, newest first, cap 64, written only when non-empty, purged with item tombstones; 03 §5)
}

Field = {
  "id":          bytes(16)      required in version 2 (2026-10-31); the field's stable identity, random v4; derived for version 1 files (§9)
  "name":        tstr           a label, NOT unique within an item and may be empty (2026-10-31; was "unique within item" before field ids); e.g. "Username", "Password", "totp", "url", "notes", or user-defined
  "kind":        "text" | "password" | "totp" | "url" | "notes" | "email" | "date" | "month_year" | "section"   ("number" removed 2026-10-30; an old "number" reads as an unknown kind and is preserved. "section" added 2026-10-31, new enum string, no bump: a visual heading; name is the heading text, value is empty and ignored (core stores it as given); never sensitive; skipped by CSV export and search; set_field on it writes no history; merges by id and stamp like any field; older readers keep it as an unknown kind)
  "value":       tstr           for "totp": full otpauth:// URI
  "modified_at": u64            unix millis
  "section":     tstr | null    optional grouping label
}

HistoryEntry = { "value": tstr, "replaced_at": u64, "field_id": bytes(16) (version 2, optional; the field the value belonged to) }
AttachmentRef = { "id": bytes(16), "name": tstr, "size": u64, "key": bytes(32), "chunk_nonces": [bytes(24)], "added_at": u64 }
```

`attachments` is kept sorted by `(added_at, id)` in memory and on disk (since 2026-11-01). Any order is accepted on read and normalised without a restamp, so a merge of a vault with its own copy is a no-op and two devices serialise the same bytes.

### Attachments (v1.1, no version bump)

One immutable encrypted blob per attachment at `<name>.vault/attachments/<id as 32 lowercase hex>.bin` (package layout, 03 §1). The item keeps only the `AttachmentRef` inside `ct`, so names, sizes and keys are encrypted and the reference is authenticated with the item. Replacing a file is a new id; blobs are never rewritten.

```
chunk_size   = 1 MiB (1_048_576 bytes); the last chunk may be shorter; a 0-byte file has one empty chunk
chunk_count  = len(chunk_nonces) = ceil(size / chunk_size), at least 1
blob         = ct_0 || ct_1 || ... || ct_{n-1}          (each ct_i = plaintext chunk + 16-byte tag)
ct_i         = XChaCha20-Poly1305(key = ref.key, nonce = ref.chunk_nonces[i], plaintext = chunk_i,
                 AAD = vault_id || ref.id || i_be32 || chunk_count_be32 || attachment_version_be16)
attachment_version = 1   (constant, independent of the file's format_version, so a future FORMAT_VERSION bump never invalidates existing blobs)
```

`ref.key` is 32 random bytes from `OsRng` per attachment. The derived `attach_key` in §3 is reserved and unused in v1.1. The AAD binds every chunk to its vault, attachment, position and total count, so chunks cannot be swapped, reordered, truncated or moved between vaults; a short or long blob fails on the chunk count. Maximum `size` is 100 MB (100_000_000 bytes); larger files are refused before encryption. Readers and writers stream chunk by chunk and never hold a whole blob in memory.

`vault-core` exposes `attachment::seal(vault_id, ref, reader, writer) -> (ref, bytes_written)` (consumes the ref: one ref, one seal; a retry needs a new ref so nonces are never reused) and `attachment::open(vault_id, &ref, reader, writer)` streaming helpers (bytes in, bytes out; no I/O). Every write path validates a ref (size ≤ cap, nonce count = chunk count) so an unreadable ref can never be written. Phase: `v1-attach.vault` fixture with one item carrying two attachments (empty file, 3-chunk file) plus their blobs under `tests/fixtures/v1-attach.vault.attachments/`.

Unknown `kind` strings on items and fields are not errors: the reader keeps the original string (`kind_raw`) and the writer re-emits it. Apps treat a field of unknown kind as sensitive (masked) because a newer version may have added a secret kind.

Field `modified_at` is the merge unit (see `03-sync.md`). An item's top-level `modified_at` must equal `max(field.modified_at, deleted_at, metadata change)`; parsers do not enforce this but merge relies on it, so the writer must maintain it.

### ManifestRecord

```
{
  "t":      "manifest"
  "nonce":  bytes(24)
  "ct":     bytes     XChaCha20-Poly1305( CBOR([ [id, modified_at], ... ] sorted by id) )
}
```

AAD = `vault_id || item_count_be32 || format_version_be16 [|| header_digest]`. Encrypted with `manifest_key`.

`header_digest` (v1.1, owner-approved 2026-10-30) is appended **only when the header carries `slots_modified_at`**: `SHA-256(canonical CBOR of { "kdf": <kdf map>, "slots": [<slot maps, in header order, including opaque slots>], "slots_modified_at": u64, "slots_device_id": bytes(16) if present })`, 32 bytes. Files without the stamp (every v1.0 file and all committed fixtures) keep the exact old AAD and stay byte-identical. Because the manifest is sealed under a key derived from `vault_key`, only a device holding the vault key can produce a header that verifies: a stripped, re-stamped, replaced or spliced header fails the manifest tag on every unlock path, including `unlock_with_key`. This is what makes the header merge in `03` §5 safe against a file-writing attacker. Fixture: `v1-stamped.vault` (header with stamp, device id and digest-bound manifest).

On unlock, the decrypted manifest must match the `(id, modified_at)` pairs of the item records exactly. Mismatch → `VaultError::Tampered(TamperKind::Manifest)`. This catches an attacker dropping items, duplicating items, or rolling an item back to an older ciphertext they captured earlier.

## 5. Nonces and randomness

All nonces are 24 bytes from `OsRng`. Never derived, never counted. A fresh nonce on every write of every record.

## 6. KDF calibration

`kdf::calibrate(target: Duration) -> KdfParams` — start at defaults, double `m_cost` until a single derivation takes ≥ target (default 500 ms) or hits 1 GiB. Run on vault creation and offered in settings. Params are per-vault; a vault created on a fast machine is slower to open on a slow one, which is acceptable.

## 7. Errors

```rust
pub enum VaultError {
    BadMagic,
    UnsupportedVersion(u16),
    Truncated,
    Malformed(String),           // CBOR / structural
    WrongPassword,               // every password slot failed to unwrap
    NoUsableSlot,                // no slot of a kind this version can unlock (decided from plaintext, before Argon2)
    Tampered(TamperKind),
}
pub enum TamperKind { Header, Item(Uuid), Manifest, ItemCount }
```

`WrongPassword` and `Tampered(Header)` are indistinguishable at the crypto level (both are AEAD tag failures on slots). Report `WrongPassword` when at least one password slot exists and all fail, and the header parsed cleanly; report `NoUsableSlot` when there is no password slot at all (for example a file written by a newer version whose slot kinds this version does not know); report `Tampered(Header)` only on structural damage. Do not try to be cleverer than that.

## 8. Test vectors

Phase 1 must commit:

- `tests/fixtures/v1-basic.vault` — password `correct horse battery staple`, 3 items (login with totp, note, card), created with fixed KDF params `m=8192,t=1,p=1` so tests are fast.
- `tests/fixtures/v1-empty.vault` — same password, 0 items.
- A test that regenerates `v1-basic` from a fixed seed and asserts byte-equality is **not** required (random nonces), but a test that parses, unlocks, and asserts the item contents is.

## 9. Versioning

`FORMAT_VERSION` bumps only on incompatible layout changes. Adding optional CBOR map keys is **not** a bump; readers ignore unknown keys, writers preserve unknown keys they read (store them as `Vec<(Value, Value)>` extras on each struct). This is how v1.1 adds attachments without a bump. New enum strings (slot kind, item kind, field kind) are also **not** a bump: readers preserve them as described in §2 and §4.

**Version 2** (2026-10-31) adds the required field `id`. A version 1 file is read by deriving each field's id deterministically: UUIDv5 with the item id as namespace over the bytes `"field:" || name || ":" || ordinal`, where ordinal is the number of earlier fields in that item with the same name, as unpadded decimal; ids present in a version 1 file are kept; a duplicate id within an item is Malformed. A save never changes a file's version, because every slot AAD binds the version (§2): a version 1 file stays version 1 and merely gains explicit ids, `removed_fields` and `field_id` as keys older builds preserve as extras. `UnlockedVault::upgrade_format(password, now)` moves a file to version 2 by re-wrapping the password slots; it drops enclave, recovery and opaque slots (same contract as `rotate_vault_key`), so Touch ID must be re-enrolled; the app runs it automatically on the next password unlock of a version 1 file and says so; the CLI exposes it as an explicit command. Every version keeps its fixtures: `v2-basic.vault` carries two same-named fields, an empty-named field, a `removed_fields` marker and a history entry with `field_id`; the version 1 regenerators are historical and refuse to run. A merge never lowers a file's version: the header with the greater `format_version` wins regardless of `slots_modified_at`, so an upgrade is never undone; a slot change made on the older version after another device's upgrade (a password change or Touch ID enrolment) is dropped by the merge and must be redone on the upgraded vault.

Every `FORMAT_VERSION` keeps its fixtures under `tests/fixtures/` forever, and a test opens every fixture in that directory with the current reader. `v1-forward.vault` carries an opaque slot, an unknown item kind, an unknown field kind, and unknown keys at every level. `v1-icon.vault` carries a symbol icon with a colour, a logo icon without one, and an icon-less item. `v1-meta.vault` carries one item with `created_at` and a section heading followed by two text fields, and one item with no `created_at` key.

## 10. Non-goals of the format

- No compression (compressing before AEAD leaks length patterns and buys little at this size)
- No per-item keys (one HKDF-derived item key; per-item AAD gives the isolation we need)
- No "encrypted-but-searchable" indexes; search is in memory on the unlocked vault
