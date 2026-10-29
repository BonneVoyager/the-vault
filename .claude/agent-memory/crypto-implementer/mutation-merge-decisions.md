---
name: mutation-merge-decisions
description: Settled interpretations for vault-core package P4a (update/set_field/delete/purge and merge_from per 03 §5) — error mapping, restamp rule, field order, history normalisation, MergeReport counting
metadata:
  type: project
---

Decisions settled while implementing `crates/vault-core` P4a (2026-10-28). Later packages
(slot management, vault-sync, CLI) must stay consistent with these. See also [[format-decisions]].

**Module placement:** `merge` lives at `src/vault/merge.rs` (`pub mod merge;` inside `vault.rs`,
`pub use merge::MergeReport;` there) because `lib.rs` was frozen that round. Spec 02 lists it as
a crate-root module; `lib.rs` should later add `pub use vault::{MergeReport, merge};`. Until then
callers reach it as `vault_core::vault::MergeReport`.

**Error mapping (error enum frozen):** unknown item id -> `Malformed("unknown item <uuid>")`;
unknown field in `set_field` -> `Malformed("unknown field \"name\" on item <uuid>")` (field
names are not secret). `set_field` never creates a missing field. `merge_from` returns
`Result<MergeReport, VaultError>` (spec signature was bare `MergeReport` but text says "else
error"); mismatch -> `Malformed("vault_id mismatch")`. If a `NotFound`/`VaultMismatch` variant is
ever added, swap these three spots.

**Monotonicity rule (security review 2026-10-28, fix round 1):** every local mutation stamps
`stamp(now, previous) = max(now, previous + 1)` -- strictly advancing, never a tie. Applied to:
changed/new field timestamps in `update`, the field stamp and history `replaced_at` in
`set_field`, `deleted_at` in `delete` (`deleted_at = modified_at = stamp(now, modified_at)`),
and the item floor passed to `restamp(item, floor, device_id)` which sets
`modified_at = max(item.modified_at, floor, fields, deleted_at)`. `insert` over an existing id
uses floor `max(now, existing.modified_at + 1)` and drops the old `record_extras`.
Why `+1` and not `max(now, prev)`: with `max` alone a skewed edit ties the untouched peer copy on
`(modified_at, device_id)` (both copies carry the same device_id after unlock), and the tie
resolves to "ours" on each side -> not commutative, and a skewed delete silently resurrects
(guarantee 9 breaks). `update` matches fields by `name` against the pre-call clone; new fields
get `stamp(carried-or-now, before.modified_at)`; `update` ignores changes to `item.id`.
`purge_tombstones_older_than(cutoff)` is strict `<`.

**History:** `normalize_history` (merge.rs, `pub(crate)`) sorts by `replaced_at` desc, ties by
value asc, dedups exact `(value, replaced_at)`, truncates to `HISTORY_CAP = 10`. `set_field` on a
`password` field always pushes the previous value (even if equal) then normalises. Merge unions
both histories, then for each `password` field that lost a true conflict (both present,
different values) pushes `(loser.value, loser.modified_at)` UNLESS that value is already in the
union by value (the "only one side edited" case; otherwise merging an untouched copy would
report a change). Non-password losers are dropped.

**Merge item rules:** winner-by-metadata = greater `modified_at`, tie greater `device_id` bytes
(`Uuid` `Ord`), tie ours. Field order in a merged live item = metadata winner's order, then the
loser's extra fields in loser order (commutative except on an exact `(modified_at, device_id)`
tie). Both tombstones -> metadata winner wholesale. Result `modified_at = max` always, even when
a tombstone/live clone wins. Absent-in-ours items are cloned together with their `record_extras`.

**Merge timestamp bump (final security pass 2026-10-29):** in `merge_from`, when the merged item
differs from ours but `max(ours, theirs).modified_at == ours.modified_at`, stamp
`ours.modified_at + 1`. Otherwise the new file keeps the old `(id, modified_at)` pair with new
content and splicing the pre-merge record back passes the manifest check (guarantee 6). Cost:
strict one-round commutativity on `modified_at` is gone; content converges in one round, the
timestamp in two (`converge` test helper does two rounds). Never "fix" this back to plain max.
Also documented: ours' `record_extras` win for ids on both sides, metadata loser's ItemPlain
extras (v1.1 attachments) are dropped; purge cutoff must exceed offline window + skew (a stale
live peer copy resurrects a purged tombstone); duplicate field names tolerated, first wins.
`search::fold`/`host_of` return `Zeroizing<String>`; `totp::parse_uri` never lowercases the URI.

**MergeReport counting:** `added` = ids new to ours (live or tombstone); `updated` = both present,
merged != ours, result live (resurrections included); `deleted` = ours was live, result tombstone;
`unchanged` = merged == ours, plus ids present only in ours. `changed()` = added+updated+deleted>0.
`merge::item_eq` is the public structural equality (Item has no PartialEq).

**Why:** these are the points where 02/03 were silent; changing them changes merge outcomes or
error matching in vault-sync/CLI.
**How to apply:** route any new mutation through `stamp` + `restamp`; never sort fields by name;
never weaken `+1` to `max`; reuse `normalize_history` wherever history is touched.
