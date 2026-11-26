---
name: merge-law-analysis
description: 2026-11-01 analysis of the three failing merge_props laws (commutativity, monotone stamps, N-device convergence) — all classified spec-conformant (b), with the precise laws that DO hold (verified by a scratch proptest run) and the asymmetry of the 03 §5 "+1 bump"
metadata:
  type: project
---

Owner asked (2026-11-01) whether the three failing laws in `tests/merge_props.rs` (proptest,
added by a routine agent) are merge defects. Verdict: all (b) — spec-conformant, the roadmap
law in 00-overview is stricter than 03 §5. No `src/` change was made for them; the owner
decides. See [[field-identity-decisions]] (bump/tie-break history), [[attachment-decisions]].

**Root cause shared by F1 and F3:** the 03 §5 rule "a merge that changes content without
changing `modified_at` bumps it by one" is one-sided by construction: only the side whose
content changed bumps, the other side (already holding the winning content) stays, so
`a.merge_from(b)` and `b.merge_from(a)` can differ by exactly 1 ms in `modified_at` with
identical content. It cannot be made symmetric: the stay-side has nothing to change (bumping
it would break idempotence) and the bump is required for 02 guarantee 6 (manifest binds
`(id, modified_at)`). With N devices the bumps cascade (a device that bumped holds the strict
max, a same-stamp pair with different device ids makes the smaller-id side adopt the other's
device id and bump again).

**Laws that hold (scratch proptest, 256 cases each, 2026-11-01):**
- Commutativity: content (everything but `modified_at`) equal after one exchange,
  `modified_at` within 1; equal (incl. `modified_at`) after a second exchange.
- Convergence: N devices converge within N rounds (so 2 for 2, matching the spec); N+1 when
  the `removed_fields` cap fires (3 for 2 devices, matching the spec); content converges
  within two rounds for N devices.
- Monotone: `modified_at` never decreases; attribute/field stamps never decrease across a
  step when the item is LIVE before and after. They legitimately drop when a tombstone wins
  (row 3 of the item table: the deleting side's snapshot replaces the item wholesale) and
  when a resurrecting live copy replaces a tombstone (the tombstone's *effective* unstored
  title stamp was its `modified_at`; the live copy's pinned stored stamp is older). Neither
  is user-visible: `items()` hides tombstones, 02 has no restore API, and a resurrection
  takes the live side wholesale so tombstone attributes never surface.

**Tightening IMPLEMENTED 2026-11-26** (security review M-01, see
[[symmetric-restamp-decisions]]): a true merge (record differs from BOTH inputs, `created_at`
included) is stamped `max(ours, theirs) + 1` on both sides, making those merges exactly
commutative; the peer's record at an EQUAL stamp also restamps (our own record used the
pair); only the peer's record at a strictly greater stamp is adopted verbatim, so ties
stay one-sided and converge next round (`same_but_bump` |delta| <= 1 still right). **Marker-cap bound settled 2026-11-26:** `devices_converge_in_n_plus_one_or_n_plus_two_rounds_when_the_marker_cap_fires`
asserts N+1 for two devices and N+2 for three and four (`n in 2..=4`, rounds reuse the four
generated orders cyclically, every device must end <= FIELD_TOMBSTONE_CAP). GOTCHA: `ordered`
zips `pairs(n)` with the key list, so the inner key vec must have >= n*(n-1) entries (12 for
n=4) or pairs are silently skipped and a device is never merged into (looked like a bound
failure: one device still at modified_at 10). The n=3 N+2 case is pinned deterministically
in `replay_marker_cap_three_devices_need_n_plus_two` (strategy changes cannot lose it); the
`proptest-regressions` file keeps its two seeds (tracked). Ledger `mi06` in
qa/spec-checks/tests/merge_ids.rs re-expected to the restamp rule (renamed
`mi06_created_at_minimum_is_kept_and_restamps_as_a_record_change`).
Mechanism (replayed from the seed, 70 markers owned 66/3/1): the cap's "absent on both input
sides" predicate lets a pair drop a marker while the third device still holds the field;
it resurrects at the next contact and the marker is re-learnt from a peer that kept it —
NOT a stamp cascade. Measured ~12k random cases (uniform + skewed ownership, n=3,4): max
N+1; only the seed needs N+2. Capping to the newest 64 unconditionally would be provably
tight but resurrects fields with two devices (merge_hunt L1), so the algorithm was kept.
All 7 laws pass at 4000 cases. A scratch measurement test (`tests/scratch_cap.rs`) was used
and deleted; rebuild it if the bound is questioned again.

**Why:** the owner wants the proptest file to assert laws the spec actually promises before
it becomes a gate; both 2026-10-31 bug-hunt H-findings were real law violations, so the
distinction matters.
**How to apply:** if asked to fix `merge_props.rs`, replace the three laws with the ones
above (content-commutativity + second exchange; N rounds / N+1; live-only attribute
monotonicity, modified_at always) rather than touching `merge.rs`.
