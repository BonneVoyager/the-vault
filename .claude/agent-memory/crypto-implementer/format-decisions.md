---
name: format-decisions
description: Settled vault-core format/AAD/canonical-CBOR decisions and spec interpretations from package P2 (format, crypto, kdf, LockedVault/UnlockedVault) — keep later packages consistent
metadata:
  type: project
---

Decisions settled while implementing `crates/vault-core` P2 (2026-10-28). Later packages
(update/set_field/delete, slot management, merge) must stay consistent with these.

**AAD layouts (byte-exact, all BE):**
- slot: `b"RVLT" || version u16 || vault_id(16) || slot.id(16) || kind utf8 ("password" etc, no terminator)` = 46 bytes for password.
  Spec wrote `format_version` without width; chose the u16 prefix width (stricter reading).
- item: `vault_id(16) || item.id(16) || modified_at u64(8) || version u16(2)`.
- manifest: `vault_id(16) || item_count u32(4) || version u16(2)`; count = number of ItemRecords incl. tombstones.
- `version` is the one READ FROM THE FILE PREFIX (stored as `Header.format_version`), not the
  compile-time const — security review (2026-10-28) required this. Builders
  `format::{slot_aad,item_aad,manifest_aad}` take it as first arg. Version 0 -> `UnsupportedVersion(0)`.

**KDF bounds (security review):** `KdfParams::validate` — all costs non-zero, m_cost <= 1 GiB,
t_cost <= 16 (was 64 until 2026-10-30, V-08), p_cost <= 64 — enforced in `Header::from_value`
(-> `Malformed`) and `derive_kek`.
Never remove: an uncapped header m_cost makes Argon2 allocate terabytes before the password check.

**Canonical CBOR approach:** build `ciborium::Value` trees, run `format::canonicalize` (recursive
sort of map entries by pure bytewise order of the encoded key, RFC 8949 §4.2.1 — NOT the RFC 7049
length-first rule; review item), then `ciborium::into_writer`. `encode` pre-sizes via `estimate_len`.
Item/Field `Debug` prints `[N extras redacted]` (extras may hold v1.1 attachment keys).
Extras are merged into the same map and sorted with known keys. Parsers reject duplicate keys
(`MapReader`), trailing bytes (`decode_exact` on a shrinking `&[u8]`; ciborium never over-reads).

**Unlock check order:** derive KEK once (same for all password slots) -> try each password slot
-> all fail = `WrongPassword` -> decrypt every item in file order (first failure =
`Tampered(Item(id))`) -> decrypt manifest -> compare records sorted by id against manifest
*as stored* (manifest must already be id-sorted; byte order = `Uuid` `Ord`).
Items before manifest so a foreign record reports `Item`, not `Manifest`.
`TamperKind::Header` and `ItemCount` are defined but never produced (spec reserves them).

**Spec interpretations / deviations:**
- `UnlockedVault::create` sets `created_at = 0` (core has no clock); `create_with_created_at(.., secs)` added.
- `unlock` yields `device_id = Uuid::nil()`; `set_device_id` added (spec gives no source for it).
- `get(id)` returns tombstones too; `insert` with an existing id replaces.
- Unknown `kdf.alg`, unknown record `t` -> `Malformed`. Unknown slot/item/field `kind` strings are
  now TOLERATED (2026-10-29) — see [[forward-compat-decisions]].
- Argon2 rejecting header params (e.g. m_cost < 8*p_cost) -> `Malformed`, not `WrongPassword`.
- `attachments`: parsed into `Item.attachments` since 2026-10-29 — see [[attachment-decisions]]
  (the earlier "kept in extras" behaviour is gone; a colliding extra is dropped on write).
- `history` optional on read (missing/null = empty); always written. `HistoryEntry` has no extras.
- Record-level unknown keys (plaintext, unauthenticated) kept in `UnlockedVault.record_extras`
  / `manifest_extras` keyed by item id and re-emitted.
- Dep versions: argon2 0.5, chacha20poly1305 0.10, hkdf 0.12, sha2 0.10, rand 0.8 (rand_core 0.6
  matches chacha20poly1305), secrecy 0.8 (spec names `SecretVec`), ciborium 0.2, thiserror 2.
- Fixtures `tests/fixtures/v1-basic.vault` / `v1-empty.vault` (01 §8) NOT yet generated.
- Slot management (P4b) decisions live in [[slot-management-decisions]].
- Header `slots_modified_at` (optional, written only when set) and the header merge live in
  [[header-merge-decisions]] (2026-10-30).

**Why:** these are the points where 01/02 were silent or ambiguous; changing any of them later
changes bytes on disk or error mapping.
**How to apply:** reuse the AAD builders and `canonicalize`; do not add a second encoding path;
when adding slot management, keep `slot_aad` and derive KEK once per unlock.
