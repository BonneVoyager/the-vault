---
name: history-tombstone-decisions
description: Settled vault-core history decisions — which field kinds keep history (merge::keeps_history = Password | Pin since 2026-11-15), Item.removed_history stamp list, CBOR shape, remove_history_entry/clear_history semantics, merge drop rule, set_field stamp guard, purge, cap
metadata:
  type: project
---

Decisions settled while adding removable history entries (01 §4 `removed_history`, 03 §5)
to `crates/vault-core` on 2026-10-29. Mirrors the attachment-tombstone design in
[[attachment-decisions]]; see also [[mutation-merge-decisions]].

**Model:** `Item.removed_history: Vec<Millis>` = `replaced_at` stamps of deleted history
entries, never the value. Newest first, dedup, cap = `vault::HISTORY_CAP` (10, same constant
as history itself; no separate constant). CBOR key `"removed_history": [u64]`, OPTIONAL,
written only when non-empty (v1 bytes/fixtures unchanged); missing/null reads as empty;
non-integer entry = Malformed. Canonical key order puts it after `attachments` and before
`removed_attachments` (length-first ordering). Debug prints the stamps (no secret).
`item_eq` and the tests' `assert_item_eq` compare it (the latter now also compares
`removed_attachments`).

**API:** `remove_history_entry(item, replaced_at, now)` removes EVERY entry with that stamp
(a merge can leave two values on one stamp; the marker is keyed by stamp alone so they go
together), unknown stamp -> `Malformed("unknown history entry ..")`, restamp via
`stamp(now, modified_at)`. `clear_history(item, now)` drains all entries into the list; an
item with EMPTY history is a no-op (no restamp) so it is idempotent. Cap overflow on clear
(earlier removals + full history) drops the oldest stamps; a peer may in theory resurrect
those — accepted by lead. `insert`/`try_insert`/`update` normalise the list (no dropping of
history entries there; only merge drops).

**Merge (live+live):** union both stamp lists, normalise, then `history.retain(stamp not in
set)` applied AFTER conflict-loser entries are pushed (a loser carrying a removed stamp is
dropped too), then the usual normalize_history. Item-tombstone cases clone wholesale as
before (a tombstone keeps its history and empty list).

**Which kinds keep history (2026-11-15):** `vault::merge::keeps_history(kind)` = `Password | Pin`
(pub(crate), lives in merge.rs, not on FieldKind) is the ONE predicate for both sites:
`set_field` history push + removed-stamp guard, and the merge conflict-loser rule. Owner
decision 2026-11-15: a PIN keeps the history disclosure like a password (specs 01 §4 "pin",
02 "write", 03 §5 all amended). `Pin` is a new enum string, no FORMAT_VERSION bump, no
fixture; older readers see `Other`/`kind_raw="pin"` (masked, no history). Every other kind,
including `Other`, writes nothing. If a future kind should keep history, change only that
predicate and add a pin-style pair of tests (`tests/mutation.rs`
`set_field_pin_pushes_history_with_field_id_and_skips_removed_stamps`, `tests/merge.rs`
`pin_conflict_loser_lands_in_history_on_both_sides`). Equal-stamp history entries sort by
value asc (normalize_history), so expected lists in tests must honour that.

**set_field guard / unique stamps (2026-11-15):** for a history-keeping field, `at =
stamp(now, field.modified_at)` is advanced `while removed_history.contains(at) ||
history.any(replaced_at == at)`; the field's `modified_at` and the history stamp stay
equal; the walk is `checked_add` and computed BEFORE the value swap, so passing u64::MAX (a
peer file may carry such stamps) returns `Malformed("history stamps .. exhausted ..")`
with nothing mutated (security review 2026-11-15: `saturating_add` hung). The
removed-stamp half is unreachable under monotone stamps (only a timestamp moved
back through `update` triggers it); the history half is the normal case when the app saves
two history-keeping fields (password+pin, two passwords) with one `now` — without it both
entries shared a stamp and `remove_history_entry` (stamp-keyed) took both. Invariant:
every history entry MINTED by set_field has a unique stamp per item. Deliberate exception:
the merge conflict-loser push keeps `replaced_at = loser.modified_at` (03 §5) and so can
twin the entry the winner recorded when replacing it; bumping in merge would depend on
merge order and diverge across devices, so those twins are still removed together. Tests:
`tests/history.rs` `set_field_never_reuses_a_removed_stamp`,
`set_field_on_two_history_fields_with_one_now_gives_distinct_stamps`,
`set_field_fails_instead_of_hanging_when_stamps_reach_u64_max`.

**Purge:** `purge_tombstones_older_than(cutoff)` also drops stamps `< cutoff` on every item,
no restamp, return value still counts items only.

**Tests:** `tests/history.rs` (6 tests): remove/restamp/errors/twin stamps, clear + cap +
idempotence, cap/purge/insert-normalise, exact CBOR shape + key order + null/missing/bad,
merge both ways (+ both-sides-removed, conflict-loser drop, tombstone wholesale),
set_field guard.

**Why:** points where 01 §4 / 03 §5 / lead brief were silent; vault-app's history UI and
vault-sync's merge expectations depend on them.
**How to apply:** UI "delete this history entry" -> `remove_history_entry` with the entry's
`replaced_at`; "clear" -> `clear_history`. Never edit `history`/`removed_history` through
`update` from app code.
