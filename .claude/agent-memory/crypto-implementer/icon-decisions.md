---
name: icon-decisions
description: 2026-10-31 IC-1 per-item icon (ItemIcon, Item.icon, CBOR "icon" map, v1.2 no bump) — shape, null/missing rule, colliding-extra rule, merge-as-metadata, v1-icon fixture is stamped and kind-less
metadata:
  type: project
---

Owner decision 2026-10-31: items get an optional icon choice, interpreted by the app, stored
by core (core validates nothing beyond CBOR types). Implemented in `crates/vault-core`
without a `FORMAT_VERSION` bump (01 §9: added optional key). See [[format-decisions]],
[[attachment-decisions]], [[item-kind-removal-decisions]].

**Model:** `item::ItemIcon { kind: String, value: String, color: Option<String>, extras }`,
derives `Clone, PartialEq, Debug` only — NO `Eq` because `extras` holds `ciborium::Value`
(only `PartialEq`); the lead asked for Eq, deviation reported. `ItemIcon::new(kind, value)`.
`Item.icon: Option<ItemIcon>`, `Item::new` -> None, in the manual Debug (printed in full,
not secret). Exported from the crate root.

**CBOR:** `ItemPlain.icon` = `{ "kind": tstr, "value": tstr, "color": tstr? }` + extras;
`color` key emitted only when Some. Item-level `icon` key written only when `Some`
(so every pre-icon fixture is byte-identical). Canonical order inside the map: kind,
color, value; at item level `icon` sorts FIRST (4-byte key, 'i' < 't' of `tags`).
Reader: missing OR null -> None (same tolerance as `attachments`); anything else goes
through `MapReader` (`icon_from_value`): non-map, missing kind/value, non-text kind/value/
color, duplicate keys -> `Malformed` (whole unlock fails). Null `color` -> None.
Colliding `kind`/`value`/`color` extras inside the icon map are dropped by `build_map`.
An `icon` entry in `Item.extras` while `item.icon == None` is written VERBATIM (same rule
as `removed_history`/`removed_attachments`: key reserved only while present); the reader
never produces one, so only API misuse can. `tests/icon.rs` relies on this to write a
malformed icon through the normal writer.

**Merge:** icon is metadata like favorite/tags: `merge_live` copies `winner.icon`;
`item_eq` and tests' `assert_item_eq` compare it; no field-level merge. `update` restamps
unconditionally so an icon-only edit is noticed. No new `UnlockedVault` method.

**Fixture:** `tests/fixtures/v1-icon.vault` (ids 0x08 symbol+colour "key.fill"/"#3B82F6",
0x09 logo "github.com" no colour, 0x0C none; all at T0+60, tag `login`, username/password
fields; password = PASSWORD, `KdfParams::for_tests()`), built by ignored
`regenerate_icon_fixture`, read via `std::fs`. It was created AFTER stamp-at-create and
AFTER the kind removal, so `every_fixture_in_the_directory_opens` now has a
`post_removal(name)` predicate (`v1-stamped` | `v1-icon`) for both "header is stamped" and
"no legacy kind extra"; min fixture count is 6. Any future fixture generated with
`new_vault()` must be added to that predicate.

**Why:** 01 §4 had no icon; the lead's brief left null handling, Eq, and key order open.
**How to apply:** never emit `icon` when None; never interpret `kind` strings in core; when
adding another optional item key, follow the same write-only-when-present rule and add a
`tests/<key>.rs` with the same shape/absent/unknown/malformed/merge/fixture coverage.
