---
name: sync-feature-decisions
description: Settled interpretations for vault-core package P3.1 (`sync` cargo feature, VaultKeyHandle, export_vault_key, unlock_with_key) — first-tag-failure = WrongPassword heuristic, handle has no Clone/Debug, rotation invalidates handles
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
other unlocks. Error-mapping heuristic (the lead's chosen interpretation): the FIRST AEAD tag
check (first item record, or the manifest of an empty vault) failing -> `WrongPassword`
("wrong vault key"); every later failure -> `Tampered(..)` as usual. Implemented as a private
`first_failure_is_wrong_key: bool` on `unlock_with_vault_key` plus `tag_failure(wrong_key,
kind)`; `unlock`/`unlock_with_kek` pass `false`. Known conflation (tested, documented): right
key + tampered FIRST record reports `WrongPassword`, while `unlock(password)` on the same bytes
still reports `Tampered(Item(id))`. `device_id` is set directly from the argument.

**Lifetime of a handle:** survives `change_password` (vault_key unchanged, guarantee 8) but
NOT `rotate_vault_key` — a stale handle on a rotated file gives `WrongPassword`; re-export after
rotation. vault-sync must drop handles when the vault locks and never persist them.

**Why:** 03 only names the method and the feature; the key-vs-tamper distinction with no slot
to verify against is inherently ambiguous, and the lead preferred the first-failure heuristic
over a separate verifier record.
**How to apply:** when vault-sync gets `WrongPassword` from `unlock_with_key`, treat it as
"cached key no longer matches the file" (e.g. another device rotated the key) and fall back to
a password prompt, not as corruption.
