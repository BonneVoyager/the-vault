---
name: slot-management-decisions
description: Settled interpretations for vault-core package P4b (unlock_with_kek, change_password, add_enclave_slot, remove_slot, rotate_vault_key, slots()) — rotation drops enclave slots, created_at=0, error mapping, slot id/nonce rules
metadata:
  type: project
---

Decisions settled while implementing `crates/vault-core` P4b (2026-10-28). vault-macos (Touch ID
enrolment) and vault-app must stay consistent with these. See also [[format-decisions]] and
[[mutation-merge-decisions]].

**Shared verification path:** `unlock` and `unlock_with_kek` both end in
`LockedVault::unlock_with_vault_key` (items -> manifest, unchanged). `unlock_with_kek` addresses a
slot of ANY kind by id; it only differs in how the vault_key is unwrapped.

**Error mapping (error enum frozen):** missing slot id -> `Malformed("no such slot <uuid>")`
(slot ids are plaintext, so the id is included); KEK length != 32 -> `Malformed("kek must be 32
bytes, got N")` (`crypto::kek_from_bytes`); slot tag failure -> `WrongPassword` (01 §7, even for
enclave slots); removing the only password slot -> `Malformed("cannot remove last password slot")`.
`change_password` with invalid new `KdfParams` -> `Malformed`, header untouched. If a
`NotFound`/`InvalidKey` variant is ever added, swap these spots.

**change_password:** verifies old via `verify_password` (derive KEK once with header params, any
password slot unwraps -> ok; AEAD tag is the only check, unwrapped bytes are never compared).
Replaces EVERY password slot (KDF params are header-wide, 01 §2): fresh id + nonce + wrapped_key,
`created_at` and slot `extras` carried over from the replaced slot. Enclave/recovery slots
untouched. `header.kdf = kdf` (its salt becomes the header salt). vault_key unchanged
(guarantee 8 test proves it via an enclave slot added before the change).

**add_enclave_slot:** `created_at = 0` (no clock); `add_enclave_slot_with_created_at(kek, secs)`
added, mirroring `create_with_created_at`. Signature has no error channel, so a KEK that is not
32 bytes PANICS (documented `# Panics`; caller generated the KEK, so it is a caller bug).

**rotate_vault_key:** verifies password, fresh `vault_key` from OsRng, re-wraps into every
password slot keeping slot id and created_at, with a FRESH nonce (same KEK + new plaintext under
an old nonce would be nonce reuse). **All non-password slots (enclave, recovery) are dropped
silently** — their KEKs are not password-derivable, so the core cannot re-wrap them; the
signature returns `()` so the dropped ids are not reported. Callers must re-enroll Touch ID
after rotation (read `slots()` before/after if ids are needed). Old `Keys` dropped ->
Zeroizing wipes old vault_key and subkeys. Items re-encrypt on next `serialize`. Previously
written bytes stay a valid independent vault under the old password AND old enclave KEKs.

**slots():** `(Uuid, SlotKind)` in header order on both LockedVault and UnlockedVault.

**lib.rs:** now has `pub use vault::{MergeReport, merge};` (merge is reachable at crate root).

**Why:** 01/02 are silent on rotation vs. non-password slots, on created_at without a clock, and
on the error channel for a mis-sized KEK.
**How to apply:** vault-macos must store the enclave slot id next to the Keychain KEK and must
re-enroll after `rotate_vault_key`; never keep an enclave slot across rotation; never re-wrap
under an existing nonce.
