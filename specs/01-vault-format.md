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
}
```

### KeySlot

```
{
  "id":          bytes(16)     UUIDv4
  "kind":        "password" | "enclave" | "recovery"
  "nonce":       bytes(24)
  "wrapped_key": bytes(48)     XChaCha20-Poly1305( vault_key ) → 32 ct + 16 tag
  "created_at":  u64
}
```

- `password` slot: KEK = `Argon2id(password_utf8_nfc, salt, m,t,p) → 32 bytes`. The password is NFC-normalised before hashing.
- `enclave` slot (phase 4): KEK is a random 32-byte key held in the Keychain, access-controlled by Touch ID. The slot itself is identical in structure.
- `recovery` slot (v2): reserved.

AAD for unwrapping any slot: `magic || format_version || vault_id || slot.id || slot.kind`. Tampering with KDF params does not break unwrap (they're not in AAD by design — otherwise you can't rotate them); it just makes derivation produce the wrong KEK and the tag fails. Tampering with `vault_id` fails every slot.

Multiple `password` slots are allowed in the format but v1 UI exposes one.

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
  "kind":        "login" | "note" | "card" | "identity"
  "title":       tstr
  "deleted_at":  u64 | null     tombstone when non-null; fields may be empty then
  "device_id":   bytes(16)      device that made the latest change
  "favorite":    bool
  "tags":        [tstr]
  "fields":      [Field]
  "attachments": [AttachmentRef]   (v1.1, empty in v1)
  "history":     [HistoryEntry]    last 10 password values, optional
}

Field = {
  "name":        tstr           unique within item, e.g. "username", "password", "totp", "url", "notes", or user-defined
  "kind":        "text" | "password" | "totp" | "url" | "notes" | "email" | "date" | "month_year" | "number"
  "value":       tstr           for "totp": full otpauth:// URI
  "modified_at": u64            unix millis
  "section":     tstr | null    optional grouping label
}

HistoryEntry = { "value": tstr, "replaced_at": u64 }
AttachmentRef = { "id": bytes(16), "name": tstr, "size": u64, "key": bytes(32), "chunk_nonces": [bytes(24)] }
```

Field `modified_at` is the merge unit (see `03-sync.md`). An item's top-level `modified_at` must equal `max(field.modified_at, deleted_at, metadata change)`; parsers do not enforce this but merge relies on it, so the writer must maintain it.

### ManifestRecord

```
{
  "t":      "manifest"
  "nonce":  bytes(24)
  "ct":     bytes     XChaCha20-Poly1305( CBOR([ [id, modified_at], ... ] sorted by id) )
}
```

AAD = `vault_id || item_count_be32 || format_version_be16`. Encrypted with `manifest_key`.

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
    Tampered(TamperKind),
}
pub enum TamperKind { Header, Item(Uuid), Manifest, ItemCount }
```

`WrongPassword` and `Tampered(Header)` are indistinguishable at the crypto level (both are AEAD tag failures on slots). Report `WrongPassword` when all slots fail and the header parsed cleanly; report `Tampered(Header)` only on structural damage. Do not try to be cleverer than that.

## 8. Test vectors

Phase 1 must commit:

- `tests/fixtures/v1-basic.vault` — password `correct horse battery staple`, 3 items (login with totp, note, card), created with fixed KDF params `m=8192,t=1,p=1` so tests are fast.
- `tests/fixtures/v1-empty.vault` — same password, 0 items.
- A test that regenerates `v1-basic` from a fixed seed and asserts byte-equality is **not** required (random nonces), but a test that parses, unlocks, and asserts the item contents is.

## 9. Versioning

`FORMAT_VERSION` bumps only on incompatible layout changes. Adding optional CBOR map keys is **not** a bump; readers ignore unknown keys, writers preserve unknown keys they read (store them as `Vec<(Value, Value)>` extras on each struct). This is how v1.1 adds attachments without a bump.

## 10. Non-goals of the format

- No compression (compressing before AEAD leaks length patterns and buys little at this size)
- No per-item keys (one HKDF-derived item key; per-item AAD gives the isolation we need)
- No "encrypted-but-searchable" indexes; search is in memory on the unlocked vault
