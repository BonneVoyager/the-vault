---
name: history-tombstone-decisions
description: Settled vault-core removable-history decisions (2026-10-29) — Item.removed_history stamp list, CBOR shape, remove_history_entry/clear_history semantics, merge drop rule, set_field stamp guard, purge, cap
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

**set_field guard:** for a Password field, `at = stamp(now, field.modified_at)` is advanced
`while removed_history.contains(at)`; the field's `modified_at` and the history stamp stay
equal. Unreachable under monotone stamps (every removed stamp is a past password stamp of
that item and the field sits at or past it); only an explicit timestamp moved back through
`update` can trigger it. Test covers both the normal-flow assertion and the crafted bump.

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
