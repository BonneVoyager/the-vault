# 01 — Vault file format & cryptography

File extension: `.vault`. One vault = one file. Attachments (v1.1) live in a sibling directory `<name>.vault.attachments/`.

All integers big-endian. All CBOR is canonical (RFC 8949 §4.2.1) so byte-equality means content-equality.

## 1. Layout

```
offset  size   field
0       4      magic              b"RVLT"
4       2      format_version     u16, currently 1
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
  "slots_modified_at": u64     optional (v1.1); unix millis of the last change to slots or kdf (password change, add/remove slot, re-calibrate, key rotation); merge takes the newer header (03 §5)
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

AAD for unwrapping any slot: `magic || format_version || vault_id || slot.id || slot.kind`. Tampering with KDF params does not break unwrap (they're not in AAD by design — otherwise you can't rotate them); it just makes derivation produce the wrong KEK and the tag fails. Tampering with `vault_id` fails every slot. Once a file carries `slots_modified_at`, the KDF params and slots are additionally bound through the manifest's `header_digest` (§4), so tampering with them is detected via the manifest on the `unlock_with_key` path (`Tampered(Manifest)`); on the password path a KDF edit still surfaces as `WrongPassword` because the slot unwrap fails before the manifest is reached.

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
  "fields":      [Field]
  "attachments": [AttachmentRef]   (v1.1, empty in v1)
  "removed_attachments": [{ "id": bytes(16), "removed_at": u64 }]   (v1.1, optional; tombstones so a removal survives merge, cap 64 newest, purged with item tombstones)
  "history":     [HistoryEntry]    last 10 password values, optional
  "removed_history": [u64]         optional; `replaced_at` stamps of history entries the user deleted (never the value), cap 10 newest, purged with item tombstones
}

Field = {
  "name":        tstr           unique within item, e.g. "username", "password", "totp", "url", "notes", or user-defined
  "kind":        "text" | "password" | "totp" | "url" | "notes" | "email" | "date" | "month_year"   ("number" removed 2026-10-30; an old "number" reads as an unknown kind and is preserved)
  "value":       tstr           for "totp": full otpauth:// URI
  "modified_at": u64            unix millis
  "section":     tstr | null    optional grouping label
}

HistoryEntry = { "value": tstr, "replaced_at": u64 }
AttachmentRef = { "id": bytes(16), "name": tstr, "size": u64, "key": bytes(32), "chunk_nonces": [bytes(24)], "added_at": u64 }
```

### Attachments (v1.1, no version bump)

One immutable encrypted blob per attachment at `<name>.vault.attachments/<id as 32 lowercase hex>.bin`. The item keeps only the `AttachmentRef` inside `ct`, so names, sizes and keys are encrypted and the reference is authenticated with the item. Replacing a file is a new id; blobs are never rewritten.

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

Every `FORMAT_VERSION` keeps its fixtures under `tests/fixtures/` forever, and a test opens every fixture in that directory with the current reader. `v1-forward.vault` carries an opaque slot, an unknown item kind, an unknown field kind, and unknown keys at every level.

## 10. Non-goals of the format

- No compression (compressing before AEAD leaks length patterns and buys little at this size)
- No per-item keys (one HKDF-derived item key; per-item AAD gives the isolation we need)
- No "encrypted-but-searchable" indexes; search is in memory on the unlocked vault
