---
name: sync-feature-decisions
description: Settled interpretations for vault-core package P3.1 (`sync` cargo feature, VaultKeyHandle, export_vault_key, unlock_with_key) — key-path error mapping via manifest probe (2026-11-21, replaced first-failure heuristic), handle has no Clone/Debug, rotation invalidates handles
metadata:
  type: project
---

Decisions settled while implementing `crates/vault-core` P3.1 (2026-10-29) for the phase-3
watcher (03 §3 step 6a). vault-sync must stay consistent with these. See also
[[format-decisions]] and [[slot-management-decisions]].

**Feature gate:** `[features] sync = []` in vault-core, off by default. Everything below is
`#[cfg(feature = "sync")]`; `tests/sync_feature.rs` has `required-features = ["sync"]` via an
explicit `[[test]]` entry (auto-discovery of the other tests is unaffected). vault-app and
vault-cli must NOT enable it; only vault-sync does.

**VaultKeyHandle:** newtype over `crypto::Key32` (`Zeroizing<[u8; 32]>`), zeroizes on drop.
No `Debug`, no `Clone`, no byte accessor; explicit `duplicate(&self)` is the only copy path.
`UnlockedVault::export_vault_key()` is the only way the vault key leaves the core. Re-exported
at crate root as `vault_core::VaultKeyHandle`.

**unlock_with_key(&self, &VaultKeyHandle, device_id):** skips all slots (no Argon2), shares
`unlock_with_vault_key` (items in file order -> manifest -> sorted-pairs compare) with the
other unlocks. Error mapping (owner decision 2026-11-21, bug-hunt L1; replaced the earlier
"first tag failure -> WrongPassword" heuristic): when an item tag fails and NOTHING has
authenticated yet, probe the manifest with the same key + same manifest AAD (header digest,
item_count). Manifest opens -> `Tampered(Item(id))` (02 guarantee 4 holds on the key path);
manifest fails too -> `WrongPassword`. After one record authenticates, every failure is
`Tampered(..)` with no probe. Vault with NO item records whose manifest fails -> stays
`WrongPassword` (only tag check, nothing to probe; a damaged manifest / rollback-to-empty is
indistinguishable from a foreign key without a verifier record = format change). Implemented
as `key_unverified: bool` on `unlock_with_vault_key` + `item_tag_failure(id, Option<probe>)`;
manifest AAD is computed once before the item loop so the healthy path still decrypts the
manifest exactly once. `unlock`/`unlock_with_kek` pass `false`. `device_id` is set directly
from the argument. Consequence for vault-sync: a tampered first record now surfaces as
`Tampered(Item)` (CorruptOnDisk), no longer `KeyMismatch`; the 02 line-84 comment
"first tag failure -> WrongPassword" is stale.

**Lifetime of a handle:** survives `change_password` (vault_key unchanged, guarantee 8) but
NOT `rotate_vault_key` — a stale handle on a rotated file gives `WrongPassword`; re-export after
rotation. vault-sync must drop handles when the vault locks and never persist them.

**Why:** 03 only names the method and the feature; the key-vs-tamper distinction with no slot
to verify against is inherently ambiguous, and the lead preferred the first-failure heuristic
over a separate verifier record.
**How to apply:** when vault-sync gets `WrongPassword` from `unlock_with_key`, treat it as
"cached key no longer matches the file" (e.g. another device rotated the key) and fall back to
a password prompt, not as corruption.
