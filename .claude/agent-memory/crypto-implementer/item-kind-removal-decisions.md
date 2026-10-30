---
name: item-kind-removal-decisions
description: 2026-10-30 removal of ItemKind / Item.kind / FieldKind::Number from vault-core (no FORMAT_VERSION bump) — legacy `kind` is an unknown key in Item.extras, importers add template tags, export lost its login gate, fixture bytes unchanged
metadata:
  type: project
---

Owner decision 2026-10-30: item categories are gone (replaced by template tags handled in
the app) and the `number` field kind is gone. Implemented in `crates/vault-core` without a
`FORMAT_VERSION` bump. Supersedes the "Item/field kinds" paragraph of
[[forward-compat-decisions]] for items (field-kind rules there still hold).

**API removed:** `ItemKind`, `Item.kind`, `Item.kind_raw`, `Item::kind_str()`,
`FieldKind::Number`, `search::Query.kind`. `Item::new(title, device_id, now)` (no kind arg).
`FieldKind::ALL` has 8 entries. `Field::kind_str()` stays (unknown field kinds still use
`Other` + `kind_raw`).

**Reader/writer rule:** `decode_item_plain` never `take`s `"kind"`, so a legacy item `kind`
of ANY CBOR type (or none) lands in `Item.extras` and `encode_item_plain` re-emits it in
canonical position; a fresh item never gains one. Proven byte-identical by
`forward_compat::legacy_item_kind_round_trips_byte_identically_and_is_never_written`. An
on-disk field kind `"number"` is now `FieldKind::Other` + `kind_raw = Some("number")`.

**Fixtures:** v1-basic/v1-empty/v1-forward/v1-attach bytes untouched. The ignored
regenerators push `(kind, "<legacy string>")` into `item.extras` so a regenerate still
produces the old layout. `every_fixture_in_the_directory_opens` now also asserts
`VaultFile::parse(b).to_bytes() == b`, exactly one text `kind` extra per item, and extras
preserved across save. Canonical extras order in v1-forward: `kind` before `x_item_future`.

**Importers:** `import::add_template_tag(item, tag)` (pub(crate)) prepends the tag at index
0 unless a tag already matches after `to_lowercase()` (source spelling/position wins).
Constants `TAG_LOGIN/NOTE/CARD/IDENTITY`. CSV and KDBX always add `login` (KDBX order:
`login`, entry tags, group path); 1PUX maps categoryUuid 003/002/004/else to
note/card/identity/login. Card `number` fields keep their name with `FieldKind::Text`.

**Export:** `export_csv` no longer blanks username/password for non-login items — every
item exports whatever `username`/`password` fields it has (interpretation: omitting a
password from a plaintext export is data loss; the lead did not specify export).

**Merge/equality:** `merge_live` and `item_eq` dropped kind comparisons; `field_content_eq`
still compares field `kind`/`kind_raw`. Test helpers `common::sample_item` now put the
template tag FIRST in `tags` (`[template, "work", "tagN"]`).

**Why:** the owner will create a fresh vault, but readers must still open every existing
fixture, and old files must round-trip byte-identically.
**How to apply:** never reintroduce an item-level kind key in the writer; treat `kind` in
`Item.extras` as opaque (do not interpret it); new importers must call `add_template_tag`.
