---
name: record-extras-merge-decisions
description: 2026-11-27 bug hunt N10/N9 + security-review gate — record-level unknown keys (ItemRecord.extras) are merge input ONLY from a peer at format >= 3 (manifest-bound); then they travel whole with the item winner and are part of same_record; unbound (<3) peer keys ignored; version-mix table, N+1 round bound for mixed fleets, test technique, record_keys_props, as_key length fix
metadata:
  type: project
---

Settled 2026-11-27 fixing bug hunt 2026-11-27 **N10** (peer record-level unknown keys dropped
for an id on both sides) and **N9** in `crates/vault-core`. No format change, no fixture, no
new AAD/digest input. Supersedes the "record_extras are outside same_record (TODO(M-01))"
line in [[symmetric-restamp-decisions]]; builds on [[v3-plaintext-binding-decisions]].

**Rule (merge.rs `merge_from`, "Extras" doc paragraph):**
- Record-level keys are unstamped item-level data: taken WHOLE (never key by key) from the
  item winner, `merge::item_winner(ours, theirs) -> Ordering`: exactly one tombstone -> the
  side `merge_items` takes whole (tombstone iff `deleted_at >= other.modified_at`);
  otherwise `metadata_order` = `(modified_at, device_id, encode_item_plain bytes)`.
  `ours_wins_metadata == metadata_order != Less` (unchanged behaviour; `merge_items` now
  routes its tombstone arms through `item_winner`).
- **Interpretation (mine):** when `item_winner` is `Equal` (same payload at the same
  stamp/device) the greater canonical CBOR bytes of the keys map win
  (`record_keys_bytes` = the bytes `format::extras_digest` hashes). Needed for symmetry:
  "keep ours" on a full tie would never converge.
- `same_record(a, a_keys, b, b_keys)` = `item_eq` + `created_at` + keys equal as canonical
  CBOR (entry order is not content). Restamp rule itself untouched: equal to ours ->
  unchanged; equal to theirs at a strictly greater stamp -> verbatim (keys included);
  else `max + 1`, reported `updated` (or `deleted`).
- A winner WITHOUT keys removes the loser's keys (no entry in `record_extras` == none).

**THE GATE (security review 2026-11-27, FIX FIRST; never remove):** my first cut applied
the rule to every peer. Record-level keys below format 3 are plaintext nothing
authenticates, so a key-less attacker could (1) launder a planted key from an old v1/v2
snapshot into our v3 manifest (any non-empty map beats the empty one on an exact tie) and
(2) pump the authenticated `modified_at` by +1 per planted key until a genuine tombstone
lost. Fix in `merge_from`: `peer_keys_bound = other.header.format_version >=
PLAINTEXT_BINDING_VERSION` and `our_keys_bound` (ours), both read BEFORE the header merge
(which can raise ours in the same call; `other` is never written).
- peer >= 3 (ours any version): the rule above. Ours < 3 adopts the v3 header in the same
  call; keys bound by the next save = peer's authenticated ones or ours read from our own
  file = exactly what `upgrade_format` binds. Accepted as "no worse".
- peer < 3, id on both: `theirs_keys` reads as `ours_keys` and `keys_from_ours` is forced:
  ours kept, peer's ignored, not compared, no restamp (pre-N10 behaviour exactly).
- peer < 3, id only on peer: ours >= 3 -> item taken WITHOUT keys; ours < 3 -> with keys
  (pre-existing behaviour, unbound either way).
- "Version" = the peer's in-memory header version: for a fresh unlock (how vault-sync gets
  a peer) that is the version its records were authenticated under; a peer upgraded in
  memory counts as the file it would write (my reading of the reviewer's point 5).
- Round bound: uniform-version fleets N rounds; MIXED fleets N + 1 (a v3 device ignores a
  <3 device until that device picked up v3 from a peer; measured, N fails). All-<3 fleets:
  keys never converge (each keeps its own), items do.
- Residual (reported, not fixed): keys planted in a device's OWN pre-v3 file get bound when
  it upgrades (pre-existing I-04 limit) and then propagate under the v3 rule once.
- A future writer that removes/changes a record-level key must restamp the item.

**TIGHTENING (owner decision 2026-11-27, package C; supersedes the "peer >= 3, ours any
version" bullet, the "accepted as no worse" answer, the N + 1 bound and the residual
above):** no version 3 manifest may ever vouch for a record-level key a pre-3 file carried.
- `upgrade_format` from below `PLAINTEXT_BINDING_VERSION` does `record_extras.clear()`
  (live + tombstones), no restamp (old record is under the old version's item AAD, cannot be
  spliced; pre-3 peers never read the keys). Already-v3 vault: no-op as before.
- `merge_from`, ours < 3 and peer >= 3: `self.record_extras.clear()` at the top (after the
  vault_id check, before the header merge), so every id merges as if ours had none; ours-only
  ids keep the item, lose the keys. Not counted as a change of the record (no restamp).
  Decided on the PRE-merge versions, not on whether the header was adopted: a v3 peer with
  an unstamped header (no writer of this crate makes one) is not adopted, ours stays < 3
  with only the peer's keys; nothing is bound below 3.
- Invariant: header version >= 3 in memory => every record key was vouched for by a v3
  manifest (both ways to reach 3, upgrade and adoption, drop the rest in the same call; no
  setter). So NO "unlocked-under version" field is needed (reviewer's point E).
- Round bound: N rounds for every fleet, mixed included (measured at 4000 cases).
- Caller contract stated on `merge_from`: pass a vault fresh from unlock or the live vault.

**Test technique changed (upgrade no longer carries keys):** `tests/common::with_record_keys`
now also works on a v3 vault: it is a test-side *newer writer* that re-seals the manifest
(`manifest_key(bytes)`: adds an enclave slot under a known KEK to a throwaway copy, unwraps
the vault key with chacha20poly1305, HKDF `vault/manifest/v1`; RustCrypto crates from
[dependencies], no new dep). `manifest_entries(key, bytes)` decodes a manifest (3rd element
present iff keys). v3 pairs with keys = upgrade FIRST, then `with_record_keys`.
`v3-meta.vault` is frozen: its regenerator fails its own shape check (record key dropped by
the upgrade); the fixture is the committed example of a bound record key.
`record_keys_props` has a `[[test]] required-features = ["sync"]` entry (no cfg attr);
planted keys are named `evil`, bound ones `x`; invariant C checked on every v3 file.

**Header-level and ManifestRecord classes (owner approved the same day, DONE; the first
stop was on the coordinator's own stop rule, then lifted):** on the way from below 3 to 3
unknown keys the old file did not authenticate are dropped, not bound.
- `upgrade_format` from below 3 clears UNCONDITIONALLY: `record_extras`, `manifest_extras`,
  `header.extras`, `header.kdf_extras` and the kept slots' `extras`. My first cut kept
  kdf/slot keys of a STAMPED pre-3 header ("bound by the v1.1 digest"); security review
  round 3 rejected that: a pre-3 stamp can come from a blind first save (L-02) or any slot
  change, which stamps planted keys into the digest, and that persists on disk (the CLI
  never upgrades on its own). "Stamped" != "chosen by a key holder". Never reintroduce a
  stamp-based exemption. `vault_id`/`created_at` and the known kdf/slot keys stay.
- `merge_from` adopting a v3 header into a pre-3 ours (inside the `theirs_newer` branch):
  the header already comes whole from the peer; `manifest_extras.clear()` on ours. The
  peer's manifest-record keys are NOT taken ("none"): no merge rule ever moved them, every
  vault keeps its own, they are outside `MergeReport`, so there is nothing to converge.
- A pre-3 ours that does not adopt a v3 header keeps its kdf/slot/header/manifest keys in a
  pre-3 file (nothing binds them as key-holder data; fine).
- Tests in `v3_binding.rs`: `v1_forward_stays_v1_on_a_plain_save_and_the_upgrade_drops_
  every_unknown_key` (unstamped AND first-saved), `upgrade_from_a_stamped_v2_header_drops_
  every_unknown_key_too`, `no_step_before_the_upgrade_gets_a_planted_key_into_a_v3_file`
  (v1-basic, five sites, five pre-upgrade steps), `a_pre_v3_header_stamp_cannot_be_added_
  stripped_or_extended_without_the_key` (both paths; use a fixture WITH items for the key
  path, an empty vault maps manifest failure to WrongPassword), `adopting_a_v3_header_
  takes_the_peer_header_keys_and_drops_our_manifest_record_keys`, `a_v3_vault_keeps_every_
  unknown_key_through_a_no_op_upgrade_and_a_self_merge`. `tests/common::rewrite_with_key(bytes, edit)` = key-holder
  writer for ANY version (re-seals the manifest: header digest, record digests, manifest
  record digest); it is how a stamped v2 header gets bound kdf/slot keys in a test.
  `regenerate_v3_meta_fixture` calls `v3_meta_regenerator_is_historical()` (panics).
  Property test also plants `evil` in the v1 starts' header top level and manifest record.

**Consequences to remember:**
- A key a newer writer added on one side is lost if the other side (which never saw it)
  makes the later edit: same trade-off as `ItemPlain` extras, by owner's reading of 03 §5.
- Strip (`delete_permanently` / `expire_deleted`), `purge`, and `insert` over an existing id
  still DROP record-level keys; `delete`, `update`, `set_field`, `recover` keep them. The
  stripped tombstone is newer, so it now also removes the peer's keys on merge.
- Equal-stamp collision with different keys: the side with greater key bytes is
  `unchanged`, the other restamps `m + 1`, then the first adopts verbatim (2 rounds, N=2).

**Tests:** `tests/record_extras_merge.rs` (13; rule tests run on v3 pairs built by
`with_record_keys` + `upgrade_format`, gate tests on v1 and the v2-basic fixture; assert
`added+updated+deleted`, not `changed()`, because independently upgraded devices differ in
header), `tamper.rs::guarantee_6_holds_when_only_record_level_keys_are_taken` (v3),
`format.rs` unit `as_key_reports_the_real_length_of_a_wrong_length_key`. Helpers in
`tests/common/mod.rs`: `with_record_keys(v, id, keys, device)` (serialize + `rewrite` +
unlock; ONLY below v3), `record_keys(v, id)`, `splice(file, donor, id)` (moved from tamper).
No public setter for record keys (reviewer: must not exist).
`tests/record_keys_props.rs` (`#![cfg(feature = "sync")]`, 1 law, default 48 cases): 2-3
devices from a cached pool of starting files (created_at x keys x item-missing x v1/v3, no
Argon2 per case, key-path opens), script of edit/touch/delete/strip/recover/merge, checks
per merge: files open on the key path, no stamp decrease, the gate, guarantee 6 by
splicing both inputs (exception: result == ours keeps a shared pair, N7 class), then
fixpoint in N / N+1 rounds. Fails on the ungated rule and on HEAD.

**merge_props:** generators NOT extended (v3 fleet cannot be planted mid-script); the
record-key law lives in `record_keys_props.rs` instead. Both pass at
`VAULT_PROPTEST_CASES=4000` (merge_props ~145 s, record_keys_props ~160 s).

**N9:** `format::as_key` read `b.len()` after `b.zeroize()` (`Vec::zeroize` truncates);
capture the length first. Lengths are not secret; bytes never go in messages.

**Why:** 01 §9 "writers preserve unknown keys they read"; v3 authenticates these keys, so
the pair `(id, modified_at)` must never be saved with keys no input carried under it.
**How to apply:** any new per-record plaintext state goes through `item_winner` +
`same_record`; never merge unknown keys key by key; avoid private intra-doc links in public
docs (rustdoc warns; 14 pre-existing).
