---
name: forward-compat-decisions
description: Settled vault-core forward-compatibility decisions (2026-10-29) — Slot/OpaqueSlot enum, SlotKind::Other(String), unit ItemKind/FieldKind::Other + kind_raw on Item/Field, NoUsableSlot error, fixture policy, which structural errors stay Malformed
metadata:
  type: project
---

Decisions settled while making `crates/vault-core` forward compatible (2026-10-29, lead's
"older app opens newer file" package). See also [[format-decisions]] and
[[slot-management-decisions]]; this supersedes the "unknown slot kind / item kind -> Malformed"
line in format-decisions.

`error.rs`/`vault.rs` comments now say `NoUsableSlot` is a documented extension to the 01 §7
enum pending a spec amendment (the enum is no longer described as "frozen"/"exactly §7").

**Rule:** tolerance applies ONLY to unknown map keys (extras, 01 §9) and unknown *enum
strings* (`slot.kind`, `item.kind`, `field.kind`). Wrong CBOR types, missing required keys,
bad lengths, unknown `kdf.alg`, unknown record `t` stay `Malformed`. No FORMAT_VERSION bump
(owner has no real vaults; v1 changed in place).

**Slots:** `Header.slots: Vec<Slot>` where `enum Slot { Key(KeySlot), Opaque(OpaqueSlot) }`.
`OpaqueSlot` has PRIVATE fields (`id()`, `kind()`, `extras()` getters) and is built only by
the parser or `OpaqueSlot::new(id, kind, extras) -> Result` which rejects known kind strings
("password"/"enclave"/"recovery" must be KeySlots) and extras keyed `id`/`kind` (review
2026-10-29: pub fields let a caller forge a nonce-less "password" slot). Only `id` (16 bytes,
REQUIRED even for unknown kinds, stricter reading) and `kind` (text) are interpreted; every
other entry is kept verbatim in `extras` and re-emitted in the slot's original position
(canonical order inside the map). **Slot ids must be unique** — `Header::from_value` rejects
duplicates as `Malformed` (an opaque slot shadowing an enclave id broke Touch ID lookup).
`unlock_with_kek` searches `filter_map(Slot::as_key)` first; an id found only on an opaque
slot -> `NoUsableSlot`, not found -> `Malformed("no such slot")`. `KeySlot` is unchanged and always has a known kind when this crate builds it.
`SlotKind` gained `Other(String)` (so it lost `Copy`; `as_str(&self)`), reported by
`Slot::kind()` / `slots()`. `slot_aad` now takes `&SlotKind`. Helpers: `Slot::{id, kind,
as_key, as_key_mut, is_key_of}`.
- `unlock`: zero password slots -> `VaultError::NoUsableSlot` (new variant, checked BEFORE
  Argon2 runs); >=1 and none unwraps -> `WrongPassword`. Opaque slots never tried.
- `change_password` leaves opaque slots untouched in place; `remove_slot` removes them by
  id; `rotate_vault_key` DROPS them (same reason as enclave: cannot re-wrap). Relabelling
  the only password slot to `enclave` now yields `NoUsableSlot`, not `WrongPassword`
  (tamper.rs updated).

**Item/field kinds (lead's revised design, 2026-10-29):** `ItemKind::Other` and
`FieldKind::Other` are UNIT variants so both enums stay `Copy` (serde derives kept; `Other`
serialises as `"other"`). The on-disk string lives on the owning struct: `Item.kind_raw:
Option<String>` / `Field.kind_raw: Option<String>` — `None` for known kinds, `Some(original)`
when kind == Other. Writer rule (`item::kind_str`): for `Other` emit `kind_raw` (fallback
placeholder `"other"` if a caller built an Other without one); for known kinds emit the known
string and IGNORE `kind_raw` (so changing kind without clearing kind_raw cannot resurrect the
old string). `Item::kind_str()` / `Field::kind_str()` are the display/on-disk accessors; the
enum's `as_str()` returns `"other"` for Other. `parse()` stays known-only (`"other"` is NOT
known); `is_other()`; `ALL` lists known variants only. `FieldKind::is_sensitive()` = Password
| Totp | Other — **the app must mask unknown field kinds**. `merge::item_eq`/`field_content_eq`
compare `kind_raw` too; `merge_live` copies the winner's `kind_raw`. CSV export has no kind
column; CLI prints `item.kind.as_str()` (shows "other" — switch to `kind_str()` if wanted).

**Downstream breakage this causes (vault-app only, lead to route):** exhaustive matches on
ItemKind/FieldKind need an `Other` arm: listing.rs:159, sidebar.rs:24/34, editor.rs:580,
detail.rs:393, state/edit.rs:310/325. Struct-update literals (`Field { .., ..bf }`) compile
unchanged. vault-cli, vault-sync, vault-macos compile unchanged. The first attempt used
`Other(String)` payloads (non-Copy) and broke 26 sites; the lead rejected that — do not
reintroduce payload variants.

**Fixture policy (tests/fixtures.rs module doc):** every FORMAT_VERSION keeps its fixtures
forever; `every_fixture_in_the_directory_opens` walks `tests/fixtures/*.vault` (parse +
unlock + re-serialize + re-unlock, same password). `v1-forward.vault` = opaque slot
"future-kind" FIRST (no nonce/wrapped_key, extra key), item kind "future-item-kind" with a
field kind "future-field-kind", extras at header/item/field level; built by the ignored
`regenerate_forward_fixture` (separate from `regenerate_fixtures` so v1-basic/v1-empty bytes
are not churned). Bootstrapping a brand-new `include_bytes!` fixture needs an empty
placeholder file first.

**Why:** the lead wants an older app to open newer files that only add things, and a clear
"newer unlock method" message instead of "wrong password".
**How to apply:** never turn an unknown enum string back into `Malformed`; any new enum in
the format needs an `Other(String)` arm and a `from_raw`; new slot operations must go through
`Slot::as_key*` and decide explicitly what happens to opaque slots.
