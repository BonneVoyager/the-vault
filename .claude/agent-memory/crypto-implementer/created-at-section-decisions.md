---
name: created-at-section-decisions
description: 2026-10-31 CS-1: Item.created_at (optional "created_at" u64 key, v1.3, no bump; merge min; excluded from item_eq and carried silently) and FieldKind::Section ("section", in ALL, 9 entries; not sensitive; export/search skip; set_field no history); v1-meta fixture
metadata:
  type: project
---

Owner decision 2026-10-31 (package CS-1): two additive item-model changes in
`crates/vault-core`, no `FORMAT_VERSION` bump (01 §9). Follow the `icon` pattern in
[[icon-decisions]]; see also [[format-decisions]], [[mutation-merge-decisions]].

**`Item.created_at: Option<Millis>`.** `Item::new(title, device_id, now)` sets `Some(now)`.
CBOR: item-map key `"created_at": u64`, written ONLY when `Some` (so every pre-v1.3 fixture
is byte-identical); reader: missing OR null -> `None`, zero is a value, any non-unsigned-int
-> `Malformed` (`opt_u64`, same arms as `icon`). Canonical position: 10-byte key, sorts
between `device_id` and `deleted_at`. A `created_at` extra while the item's own is `None`
is written verbatim (key reserved only while `Some`); a colliding extra is dropped when `Some`.
`insert` never rewrites it; `update` may change it and restamps unconditionally.

**Merge rule (immutable metadata):** `merge::merge_created_at(ours, theirs)` = min when
both `Some`, else whichever is `Some`; applied to EVERY `merge_items` outcome (live,
tombstone, both-tombstone). `item_eq` deliberately does NOT compare `created_at`, so a
differing value alone is "unchanged": no restamp, no report count, `changed() == false`.
`merge_from` still carries the min into ours in the unchanged branch (persisted with the
next save for any other reason; both sides re-derive the same min, so a missed save
converges). Test helper `common::assert_item_eq` DOES compare it (exact round trips).
Interpretation reported to the lead: the lead said "must not bump modified_at, but the
merged item still carries the min"; silent carry without a save signal is my reading.

**Importers:** CSV -> `now` (via `Item::new`). 1PUX -> `createdAt` seconds * 1000 when
present, `> 0` and an unsigned JSON number; else `now`. KDBX -> `entry.times.creation`
millis when present, representable and `> 0` (epoch = unknown, review fix), else `now` (keepass-rs `Entry::new` always sets one, so
the committed `keepass-v4.kdbx` entries carry a real wall-clock creation time).

**`FieldKind::Section`** (on-disk `"section"`, serde snake_case): a visual heading; `name`
is the heading, `value` is empty and IGNORED but NOT enforced (stored as given; the app
writes `""`). In `FieldKind::ALL` (now 9 entries) so `parse("section")` works; readers of
older builds get `Other` + `kind_raw = "section"`. `is_sensitive()` false. `export_csv`
skips Section fields on both the by-name and by-kind lookups. `search::rank` filters them
out of every field pass (a heading named `username` never matches). `set_field` on one is
allowed and writes no history (only `Password` does). Merge: by name and stamp like any
field. Value shapes on disk: `value` is still required text (null/missing/non-text ->
`Malformed`), unchanged from other kinds.

**Fixture `v1-meta.vault`** (ids 0x0D dated: `created_at = T0 - 86_400_000`, fields
`Account` section + `username` + `employee id` text, tag `login`; 0x0E undated:
`created_at = None`, one notes field, tag `note`; both at `META_AT = T0 + 70`), built by
ignored `regenerate_meta_fixture`, read via `std::fs`. Added to the `post_removal`
predicate in `every_fixture_in_the_directory_opens`; min fixture count is 7.

**Tests touched:** three canonical key-order lists (`icon.rs`, `history.rs`,
`roundtrip.rs`) now include `created_at` between `device_id` and `deleted_at` because
`sample_item` goes through `Item::new`. New `tests/item_meta.rs` (12 tests). To build a
peer copy that differs ONLY in `created_at` without a restamp: `emptied_twin` (unlock A's
bytes, `delete` all, `purge_tombstones_older_than(u64::MAX)`), insert under A's device id
at the same stamp, then switch device id.

**Outside the crate (reported, not edited):** `vault-app/src/state/edit.rs` `kind_name`
and `ADDABLE_KINDS == FieldKind::ALL` test, `screens/main/editor.rs` `value_placeholder`
are exhaustive matches / array-length comparisons that need a `Section` arm.

**Why:** the owner wants creation dates and section headings in the app without a format
bump; old files must stay byte-identical.
**How to apply:** never emit `created_at` when `None`; never let `created_at` into
`item_eq`; keep Section out of export/search/history; when adding the next optional item
key, update the three key-order lists and `post_removal` if a fixture is generated.
