---
name: field-icon-decisions
description: 2026-11-07 Field.icon (optional field-map "icon" tstr, no bump) — Some("") is None everywhere via Field::icon_name, key sorts between id and kind, change detection through field_content_eq, null/wrong-type written via extras in tests, v2-field-icon fixture
metadata:
  type: project
---

Owner decision 2026-11-07: a field may carry an optional app-interpreted symbol name.
Implemented in `crates/vault-core` without a `FORMAT_VERSION` bump (01 §9 optional key),
following the item `icon` / `section` pattern in [[icon-decisions]] and
[[created-at-section-decisions]]. Merge rules unchanged from [[field-identity-decisions]].

**Model:** `Field.icon: Option<String>` (`Field::new` -> None; manual `Debug` prints it,
nothing secret). `Field::icon_name() -> Option<&str>` = `icon` filtered to non-empty; the
writer, `field_content_eq` and (through the writer) `field_canonical_bytes` all go through
it, so `Some("")` and `None` are indistinguishable everywhere except the in-memory struct
(an `update` that sets `Some("")` keeps it in memory, does not restamp, and it reads back
`None` after a save).

**CBOR:** field-map key `"icon": tstr`, written ONLY for a non-empty name. Canonical
position: 4-byte key, sorts between `id` and `kind` (`id, icon, kind, name, value, section,
modified_at`); the one key-order list in `tests/field_id.rs` is unaffected because its
fields have no icon. Reader (`opt_text(..).filter(non-empty)`): missing, null and `""` ->
None; any other non-text -> `Malformed("field.icon ..")`. When the field has no icon the key
is NOT reserved, so an `icon` entry in `Field.extras` is emitted verbatim (same rule as
`removed_history`); this is how tests and the fixture regenerator write `null` or a wrong
type. A colliding `icon` extra while the field HAS an icon is dropped by `build_map`.

**Change detection:** `UnlockedVault::update` already restamps a field whose stamp is
untouched when `merge::field_content_eq(field, prev)` is false; the hook is the one added
`a.icon_name() == b.icon_name()` term there. `set_field` only replaces the value and keeps
the icon. No new mutator.

**Merge:** nothing new. Whole-field LWW copies the winning `Field` (icon travels); the
third tie-break (`field_canonical_bytes`) now differs on icon because the writer does.
Tests: newer-with-icon beats older-without and the reverse (a newer value edit without the
icon DROPS the icon: that is the spec's "travel together"), symmetric equal-stamp tie.

**Fixture `v2-field-icon.vault`:** item 0x14 "Field icons" (tag `login`, at `V2I_AT = T0 +
100`), fields 0x2A `username` icon "key", 0x2B `password` no key, 0x2C `notes` with
`extras = [("icon", Null)]` (so the file really carries `"icon": null`). Built by ignored
`regenerate_v2_field_icon_fixture` with `new_vault()`; added to `post_removal` and the
minimum fixture count is now 11. `tests/field_icon.rs` (17 tests) covers shape, reader
tolerance, change detection, merge, canonical bytes, pre-icon fixtures.

**Outside the crate (reported, not edited):** `vault-app/src/state/edit.rs` builds the
saved field as `Field { name, kind, value, ..stored }` and compares with `same_field`; both
need `icon` or an app-side icon edit is silently discarded. vault-cli needed no change
(uses `Field::new` only).

**Why:** the app wants per-field symbols without a bump; old files must stay byte-identical.
**How to apply:** never write `icon` for an empty name; compare icons through `icon_name()`,
never `==` on the Option; to put a null/bad `icon` on the wire use the extras route; when
adding the next optional field key, follow the same write-only-when-present rule and hook
`field_content_eq`.
