---
name: header-merge-decisions
description: 2026-10-30 bug-hunt fixes + 2026-11-27 L-02 (unstamped peer never adopted, first save stamps 1) in vault-core — slots_modified_at/slots_device_id header stamp (also set at creation; unstamped_vault() test helper) + merge_from header LWW with author tie-break (V-01/V-03), keys travel with the header, MergeReport.header_updated, slot mutators take `now`, t_cost cap 16 (V-08), generator clamps + min_length (V-07), v1-forward eight unknown-key sites (V-09), CSV formula guard bijection
metadata:
  type: project
---

Decisions settled on 2026-10-30 while fixing the external bug-hunt findings in
`crates/vault-core` (no FORMAT_VERSION bump). See [[format-decisions]],
[[slot-management-decisions]], [[mutation-merge-decisions]], [[forward-compat-decisions]].

**`slots_modified_at` (01 §2, optional, v1.1):** `Header.slots_modified_at: Option<Millis>`;
`Header::slots_stamp()` reads missing as 0. Parser: missing or `null` -> `None`; any other
non-u64 -> `Malformed`. Writer emits the key ONLY when `Some`, so every pre-existing fixture
stays byte-identical (asserted in `every_fixture_in_the_directory_opens`, both on the committed
bytes and after unlock+serialize). **`create` STAMPS (01 §2 amendment, 2026-10-30 later the same
day):** `create_with_created_at` sets `slots_modified_at = max(created_at_secs * 1000, 1)` and
`slots_device_id = device_id`, so every new vault is digest-bound from its first serialize
(`create()` with created_at 0 stamps 1). Reason: on an unstamped header a flipped password-slot
nonce was invisible to a device holding the cached key (unlock_with_key opened, the watcher
merged, nothing rewrote the slot, only the next password unlock failed). Only pre-v1.1 files
and the committed fixtures are unstamped now. Test consequence: NO fresh vault can be spliced
by hand any more; tests that need a by-hand header edit must `rewrite(common::unstamped_bytes())`
(the committed `v1-empty.vault`) and unlock the result — since L-02 (below) a `serialize` of
`unstamped_vault()` is stamped too, so splicing into `v.serialize()` is `Tampered(Manifest)`; and
`new_vault()` (created_at 1_700_000_000 s) has creation stamp T1 = 1_700_000_000_000, so a
mutation with `now <= T1` stamps `T1 + 1`. Password path on a flipped password-slot nonce is
still `WrongPassword` (01 §7 slot-first order); `unlock_with_key`/`unlock_with_kek` report
`Tampered(Manifest)`; an edit outside the slot AAD (slot `created_at`) is `Tampered(Manifest)`
on the password path too. vault-sync's `flipped_slot_nonce_is_merged_silently_and_the_password_then_fails`
(watch.rs) documented the old gap and now fails; it is the sync owner's to rewrite.

**Stamping:** `UnlockedVault::bump_slots_stamp(now)` = `stamp(now, prev)` = `max(now, prev+1)`,
called on success only by `change_password(old, new, kdf, now)` (also the re-calibration path;
there is no separate one), `add_enclave_slot(kek, now)` (slot `created_at = now / 1000` now,
no longer 0), `add_enclave_slot_with_created_at(kek, created_at_secs, now)`,
`remove_slot(id, now)`, `rotate_vault_key(password, now)`. Chosen over `_at(now)` variants
because a delegating `prev+1` default would stamp 1 on never-stamped vaults and lose to any
real clock. Downstream (vault-app security.rs/touch_id.rs, vault-sync tests) was adapted by
another agent in the same round; the workspace builds.

**Merge rule (`merge_from`, 03 §5 "Header merge"):** after the vault_id check, if
`other.slots_stamp() > self.slots_stamp()` replace `slots` (key AND opaque, in their order),
`kdf`, `kdf_extras`, `slots_modified_at`, `slots_device_id` with theirs and set
`MergeReport.header_updated = true` (`changed()` includes it, so vault-sync writes). **Tie-break
(lead's spec amendment, same day):** equal stamp -> greater `Header.slots_device_id` wins
(optional `bytes(16)` key, written only when set; `bump_slots_stamp` records `self.device_id`;
compared as `Option<Uuid>`, missing < any present). **D-9 tie-break (2026-11-06, external
review finding [9]):** the winner tuple now has a 4th component, `Header::slots_canonical_bytes()`
(pub(crate) in format.rs = `canonical_bytes(Value::Array(slots.map(Slot::to_value)))`, same
encoder as item tie-break and `Header::digest`). Full tuple: `(format_version, slots_stamp,
slots_device_id, slots_canonical_bytes)`; greater wins, loser adopts winner's slots+key.
Reason: two divergent credential changes from a CLONED/duplicated `slots_device_id` in the same
millisecond were an exact `(version, stamp, device)` tie and each side kept its own header
forever (non-convergence). Equal canonical bytes == identical slots (same change twice) ->
still "keep ours", still idempotent. `slots_canonical_bytes` is pub(crate) so integration tests
cannot call it: decide the expected winner by which password opens the converged file, not by
comparing bytes. Tests: `greater_stamp_wins_in_both_directions_and_divergent_tie_converges`
(was `..._tie_keeps_ours`), `divergent_header_tie_break_is_commutative` in header_merge.rs. Equal
stamp AND author AND slots -> keep ours (idempotence; two never-stamped headers tie). The in-memory
`UnlockedVault::device_id` is deliberately NOT used: vault-sync opens the disk copy with the
local device id, so both sides always carry the same one and the tie would never fire. Less ->
keep ours. Top-level
header extras, vault_id, created_at, format_version never change. **Keys travel with the
header:** when theirs wins, `self.keys = Keys::from_vault_key(other.keys.vault_key.clone())`
(no-op unless a rotation happened). Reason: slots wrapping key X with items under key Y is a
file nobody can open; `other` is an UnlockedVault so it holds the key its slots wrap, and no
KEK-based verification is possible or attempted. Consequence: a `VaultKeyHandle` exported
before a `header_updated` merge may be stale; a later local slot change (greater stamp) undoes
a remote rotation on merge (LWW on keys) and the other device then sees KeyRotatedOnDisk.

**KDF (V-08):** `MAX_T_COST = 16` (was 64); m <= 1 GiB and p <= 64 unchanged. Calibration never
raises t above 3.

**Generator (V-07):** `PasswordSpec::min_length()` = enabled class count, min 1 (private
`class_count`); `password` clamps `length` up to it (documented); `passphrase` treats
`words == 0` as 1. The UI/CLI should validate against `min_length()` and refuse.

**v1-forward fixture (V-09):** regenerated with unknown keys at all eight sites: header,
`header.kdf` (`x_kdf_future`), opaque slot, known password slot (`x_slot_known_future`), item
record plaintext (`x_record_future`), item payload, field, manifest record
(`x_manifest_future`). Record/manifest/kdf/key-slot extras are spliced via `VaultFile` after
encryption in `regenerate_forward_fixture`. The fixture has no `slots_modified_at`.

**CSV formula guard (OWASP):** `export::trigger_behind_quotes(cell)` =
`trim_start_matches('\'')` then starts with one of `= + - @ \t \r`. Export prefixes ONE `'`
when that holds (so `=x`->`'=x`, `'=x`->`''=x`); import strips ONE leading `'` when the rest
satisfies the same predicate. Exact inverses for every input (lead asked only for the
`'`+trigger strip; the quotes-behind generalisation is what makes the round trip lossless).
Applies to all six columns including title.

**Why:** V-01/V-03 reverted password changes and dropped enclave slots on the next save from
another device; the rest were low-severity hardening from the same report.
**How to apply:** any new slot mutation must call `bump_slots_stamp` on success only; never
take their slots without their keys; never write `slots_modified_at` when `None`; keep the CSV
predicate shared between export and import.

**W1 header_digest (owner-approved 2026-10-30, implemented):** when `slots_modified_at` is Some,
`Header::digest()` = SHA-256(canonical CBOR of {"kdf" (incl. kdf_extras), "slots" (all, in
order, opaque incl.), "slots_modified_at", "slots_device_id" if Some}) and `manifest_aad` takes
`Option<&[u8;32]>` as 4th arg (appended after version_be16; 54 bytes total). Computed from the
header in `unlock_with_vault_key` (shared by unlock / unlock_with_kek / unlock_with_key) and in
`serialize`. Unstamped files keep the exact old 22-byte AAD. vault_id/created_at/header
extras are NOT in the digest. Consequences: any by-hand slot/kdf/stamp edit of a stamped file
is `Tampered(Manifest)` (password path: a kdf edit shows as `WrongPassword` first because the
slot fails; `unlock_with_key` on an EMPTY vault reports it as `WrongPassword` by the
first-failure rule). Tests that need a custom slot layout must splice into the UNSTAMPED file
and then run the stamping mutator through the API (see forward_compat.rs). Fixture
`v1-stamped.vault` (item id 0x07.., stamp T0+50, device 0x11..) is the only stamped fixture and
the only one without a legacy `kind` extra; `every_fixture_in_the_directory_opens` compares the
stamp before/after a save instead of asserting None. `Null` for either optional key reads as
missing (no digest).

**L-02 (security review 2026-11-26, implemented 2026-11-27, no FORMAT_VERSION bump):**
(1) `merge_from` never adopts a peer header whose `slots_modified_at` is `None`
(`theirs_newer = other.header.slots_modified_at.is_some() && tuple > tuple`): both unstamped ->
keep ours whatever the canonical-bytes tie-break says; ours unstamped + theirs stamped -> theirs
under the existing tuple (its authentication is the peer's own manifest check at unlock, 01 §4;
there is no KEK check in the merge and none is possible). (2) `serialize(&self)` writes a
never-stamped header through `header_for_write()`: `stamp_header(&mut copy, 0, self.device_id)`
= stamp **1** (`max(0, 0+1)`), the SAME `stamp_header` that `bump_slots_stamp` uses. Chose 1
over "current time" deliberately: core has no clock, `serialize` has no `now` and takes `&self`
(callers in vault-sync/app hold `&UnlockedVault`), and a save that changes no slot must lose
LWW against a genuine slot change elsewhere; 1 is the smallest stamp, binds the digest, ties
only with another legacy first save (identical slots -> keep ours). The IN-MEMORY header stays
`None` after a save (it is the "no manifest vouched for this" marker the merge relies on); a
re-unlock of the written file is stamped (1, device) and a merge from it reports
`header_updated` once (harmless, identical slots/key). Residual: a planted legacy copy opened
DIRECTLY by a non-password path (Touch ID) is "ours" and gets stamped-and-saved with the planted
slot; only the password path notices. `fixtures.rs::every_fixture_in_the_directory_opens`
expects `(Some(1), Some(Uuid::nil()))` after a save of an unstamped fixture;
`assert_forward_header(locked, stamp)` takes the expected stamp. Tests: `tests/legacy_header.rs`
(3), `sync_feature.rs::l02_planted_password_slot_...` (Appendix B), `merge_props::
unstamped_headers_are_never_adopted_and_items_still_converge` (`Sim::new_legacy`, `legacy` flag
asserts `!header_updated` at every merge step; 13 s at 4000 cases), `merge_props::
mixed_legacy_and_stamped_fleet_converges_and_keeps_the_genuine_stamp` (`Sim::new_from_fixture`
with a `stamped` mask: stamped devices = `add_enclave_slot` under a per-device KEK at
`genuine_stamp(d)` = 1_000_000 + d; N rounds through `dup_legacy()` so stamp-1 headers are in
play; converged stamp = max genuine else 1; 42 s at 4000 cases). NO ARGON2 in the legacy
fleets: `legacy_base()` (OnceLock) = `unstamped_bytes()` with an enclave slot (KEK 0x5A*32,
produced via the API then spliced — tolerated because the file is unstamped) and every
device/snapshot opens with `unlock_with_kek`; `change_password` + password `dup()` had cost
~290 s. `Sim::apply` also asserts a merge never lowers `slots_stamp()`. Coordinator review 2026-11-27: SHIP; vault-sync
follow-up assigned elsewhere.
