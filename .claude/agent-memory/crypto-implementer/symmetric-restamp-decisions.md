---
name: symmetric-restamp-decisions
description: 2026-11-26 security review M-01 fix (final rule after reviewer correction): merge_from restamps max+1 whenever the result differs from ours AND (differs from theirs OR theirs.modified_at == ours.modified_at); theirs adopted verbatim only at a strictly greater stamp; same_record = item_eq + created_at; consequences, the equal-stamp trap, proptest status at 4000 cases, "fails before" test technique
metadata:
  type: project
---

Owner-approved fix for security review 2026-11-26 M-01 (spliced item record passes the
manifest check after a merge) in `crates/vault-core/src/vault/merge.rs`. See
[[merge-law-analysis]], [[created-at-section-decisions]], [[recently-deleted-decisions]].

**Final rule** (my first cut was wrong; the reviewer corrected it, see trap below). For an
id on both sides, `merged = merge_items(ours, theirs)` (sets `modified_at = max`), then with
`merge::same_record(a, b) = item_eq(a, b) && a.created_at == b.created_at`:
- `same_record(ours, merged)` -> `unchanged`;
- else if `!same_record(theirs, merged) || theirs.modified_at == ours.modified_at` ->
  `modified_at = max(ours, theirs).saturating_add(1)`;
- else (theirs' record at a STRICTLY greater stamp) -> adopt verbatim, stamp + device id.

**The trap (do not repeat):** "adopt theirs verbatim whenever the result equals theirs'
record" reopens guarantee 6 when `theirs.modified_at == ours.modified_at` and ours differs:
the saved file carries `(id, m)` with theirs' bytes while OUR pre-merge record `(id, m)` (in
a backup / the previous file) is a valid splice reverting the peer's change. The old
one-sided bump covered exactly this. Equal stamps are systematic, not "same millisecond":
`stamp(now, prev) = max(now, prev+1)` and the restamp itself produce them. The reviewer
proved it with `VAULT_PROPTEST_CASES=4000 ... merge_props`: `stamps_are_monotone` failed on
the wrong rule (tombstone at 2879 on both sides, a field removed) and passes with the final
rule; the seed is pinned in `tests/merge_props.proptest-regressions` (tracked file, keep).

**Cases covered (tests/tamper.rs `guarantee_6_holds_*`, public API, fail with the src
stashed):** Appendix A shape (result at the peer's stamp with our content); live item
resurrecting over a peer's stripped tombstone with a higher stamp; `created_at` carry with
our stamp ahead. Attachment reorder and the equal-stamp adoption fall under the same rule.
Record-level plaintext `record_extras` are outside `same_record` (TODO(M-01) on the fn).

**Behaviour to remember:**
- `created_at` carry is no longer silent: `updated`, `changed() == true`, restamp (at an
  equal stamp too: `item_meta.rs` expects `stamp + 1`). `item_eq` still ignores
  `created_at`; only `same_record` adds it.
- The equal-stamp tombstone residual (title-only tombstone reads stripped on the merging
  side) is STILL present and documented on `Item::is_trashed` and in 02 "Recently Deleted";
  test `equal_stamp_tombstone_tie_is_the_documented_residual` pins 2_001 / `!is_trashed`.
- True merges stamp identically on both sides (`merge.rs::field_level_merge_is_commutative`
  expects 11_001 on both, no-op second exchange); ties stay one-sided (`same_but_bump`'s
  |delta| <= 1 still right). `Item.device_id` after a restamp is the metadata winner's, not
  the writer's (doc note on the field).
- merge_props at 4000 cases: 7/7 pass after the marker-cap bound was corrected to N+2 for
  three devices (see [[merge-law-analysis]]); both pinned seeds in
  `tests/merge_props.proptest-regressions` pass and the file stays tracked.

**Spec:** 02 guarantee 6 states the final rule; 02 "Recently Deleted" residual sentence kept
(reworded). `specs/03-sync.md` §5 "bumps modified_at by one" not edited (outside allowed
files) — open item.

**Test technique for "fails before, passes after":** `git stash push --quiet -- <src files>`,
run with nextest `-E 'test(name)'`, `git stash pop --quiet`, re-run the full suite. A peer
copy differing only in `created_at` at a LOWER stamp: `emptied_twin` + `insert` at the base
stamp, then a content-free `update(id, later, |_| {})` on ours (a no-op closure restamps).
`insert(item, now)` cannot lower a stamp below the item's field stamps.

**Why:** the manifest binds `(id, modified_at)` only; any saved record must carry a pair no
earlier record with other bytes used — the peer's OR our own.
**How to apply:** keep both halves of the condition; never special-case metadata as a
silent carry; any new persisted item field goes into `item_eq` or `same_record`.
