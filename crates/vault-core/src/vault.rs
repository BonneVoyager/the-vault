//! `LockedVault` / `UnlockedVault` (`02-core-api.md`).
//!
//! Unlock verification order (matters for which error wins):
//!
//! 1. Every `password` slot is tried; all fail -> `WrongPassword`.
//! 2. Every item record is decrypted with its AAD, in file order; the first tag failure ->
//!    `Tampered(Item(id))`. This runs *before* the manifest check so that a record moved in from
//!    another vault is reported as `Item`, not `Manifest`.
//! 3. The manifest is decrypted with `item_count` bound in the AAD -> `Tampered(Manifest)`.
//! 4. The manifest pairs must equal the records' `(id, modified_at)` sorted by id, exactly
//!    (the manifest is required to already be in sorted order) -> `Tampered(Manifest)`.
//!
//! `unlock_with_kek` replaces step 1 with a single named slot and shares steps 2-4.
//! `unlock_with_key` (feature `sync`) skips step 1 entirely and shares steps 2-4, with the
//! *first* tag failure reported as `WrongPassword` (see its docs).
//!
//! Key-slot management (`change_password`, `add_enclave_slot`, `remove_slot`,
//! `rotate_vault_key`) only edits the plaintext header and the in-memory keys; items are
//! re-encrypted on the next `serialize` because every item/manifest key derives from
//! `vault_key` (01 §3).

use std::collections::BTreeMap;
use std::fmt;

use secrecy::{SecretString, SecretVec};
use uuid::Uuid;

use crate::crypto::{self, Keys};
use crate::error::{TamperKind, VaultError};
use crate::format::{
    self, FORMAT_VERSION, Header, ItemRecord, KeySlot, ManifestRecord, SlotKind, VaultFile,
    item_aad, manifest_aad, slot_aad,
};
use crate::item::{Extras, FieldKind, HistoryEntry, Item, Millis};
use crate::kdf::KdfParams;

pub mod merge;
pub use merge::MergeReport;

/// Maximum number of `history` entries kept per item (01 §4, 02 "set_field").
pub const HISTORY_CAP: usize = 10;

/// The error for a mutation naming an id that is not in the vault. The error enum is frozen
/// this round, so this reuses `Malformed` (interpretation; see package P4a notes).
fn unknown_item(id: Uuid) -> VaultError {
    VaultError::Malformed(format!("unknown item {id}"))
}

/// The error for an item/manifest AEAD tag failure during unlock. `wrong_key` is true only on
/// the `unlock_with_key` path (feature `sync`) while no record has authenticated yet, in which
/// case the failure is reported as the wrong vault key rather than tampering.
fn tag_failure(wrong_key: bool, kind: TamperKind) -> VaultError {
    if wrong_key {
        VaultError::WrongPassword
    } else {
        VaultError::Tampered(kind)
    }
}

/// The error for a slot operation naming an id that is not in the header. Slot ids are
/// plaintext header metadata, so the id is included.
fn no_such_slot(id: Uuid) -> VaultError {
    VaultError::Malformed(format!("no such slot {id}"))
}

/// Wrap `vault_key` into a new slot of `kind` under `kek` with a fresh id and nonce. The slot
/// AAD (01 §2) binds the file's format version, `vault_id`, the new slot id and the kind.
fn new_slot(
    format_version: u16,
    vault_id: Uuid,
    kind: SlotKind,
    kek: &crypto::Key32,
    vault_key: &crypto::Key32,
    created_at: u64,
) -> KeySlot {
    let id = Uuid::new_v4();
    let nonce = crypto::random_nonce();
    let aad = slot_aad(format_version, vault_id, id, kind);
    KeySlot {
        id,
        kind,
        nonce,
        wrapped_key: crypto::wrap_key(kek, &nonce, &aad, vault_key),
        created_at,
        extras: Vec::new(),
    }
}

/// Try `kek` against every `password` slot in `header` and return the first `vault_key` it
/// unwraps. `None` means the password was wrong (or no password slot exists). Shared by
/// `LockedVault::unlock` and `UnlockedVault::verify_password` so there is exactly one place
/// that composes the slot AAD for password slots.
fn unwrap_any_password_slot(header: &Header, kek: &crypto::Key32) -> Option<crypto::Key32> {
    header
        .slots
        .iter()
        .filter(|s| s.kind == SlotKind::Password)
        .find_map(|slot| {
            let aad = slot_aad(header.format_version, header.vault_id, slot.id, slot.kind);
            crypto::unwrap_key(kek, &slot.nonce, &aad, &slot.wrapped_key)
        })
}

/// The error for `set_field` naming a field the item does not have. Field names are not
/// secrets (they are keys such as `"username"`), so the name is included.
fn unknown_field(id: Uuid, name: &str) -> VaultError {
    VaultError::Malformed(format!("unknown field {name:?} on item {id}"))
}

/// A parsed vault: header and raw records, no key material.
#[derive(Debug, Clone)]
pub struct LockedVault {
    file: VaultFile,
}

impl LockedVault {
    /// Parse the file layout and header without any key material.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        Ok(Self {
            file: VaultFile::parse(bytes)?,
        })
    }

    pub fn vault_id(&self) -> Uuid {
        self.file.header.vault_id
    }

    pub fn kdf_params(&self) -> &KdfParams {
        &self.file.header.kdf
    }

    /// The plaintext header.
    pub fn header(&self) -> &Header {
        &self.file.header
    }

    /// Plaintext `(id, modified_at)` of every item record, in file order.
    pub fn item_summaries(&self) -> impl Iterator<Item = (Uuid, Millis)> + '_ {
        self.file.items.iter().map(|r| (r.id, r.modified_at))
    }

    /// Plaintext `(id, kind)` of every key slot, in header order. Lets the app decide whether
    /// a Touch ID (`enclave`) unlock is available before asking for anything.
    pub fn slots(&self) -> impl Iterator<Item = (Uuid, SlotKind)> + '_ {
        self.file.header.slots.iter().map(|s| (s.id, s.kind))
    }

    /// Derive the KEK once and try it against every `password` slot. If none unwraps the vault
    /// key the header parsed cleanly, so per 01 §7 this is `WrongPassword`, never `Tampered`.
    ///
    /// The KEK depends only on the password and the header-wide KDF params, so deriving it once
    /// is equivalent to the spec's "Argon2 runs once per slot" and strictly cheaper.
    ///
    /// The returned vault has `device_id == Uuid::nil()`; call
    /// [`UnlockedVault::set_device_id`] before mutating.
    pub fn unlock(&self, password: &SecretString) -> Result<UnlockedVault, VaultError> {
        let header = &self.file.header;
        let kek = crypto::derive_kek(password, &header.kdf)?;
        let vault_key = unwrap_any_password_slot(header, &kek).ok_or(VaultError::WrongPassword)?;
        self.unlock_with_vault_key(vault_key, false)
    }

    /// Unlock through one named slot with a caller-held 32-byte KEK (an `enclave` slot whose
    /// key lives in the Keychain, 01 §2). The slot may be of any kind; it is only identified
    /// by `slot_id`. Item and manifest verification is shared with [`LockedVault::unlock`].
    ///
    /// # Errors
    ///
    /// - `Malformed` if no slot has `slot_id` or `kek` is not exactly 32 bytes long (neither
    ///   is a crypto failure, so neither is reported as `WrongPassword`).
    /// - `WrongPassword` if the slot's tag fails: per 01 §7 a slot tag failure on a cleanly
    ///   parsed header is always reported as the wrong credential, never as `Tampered`.
    pub fn unlock_with_kek(
        &self,
        slot_id: Uuid,
        kek: &SecretVec<u8>,
    ) -> Result<UnlockedVault, VaultError> {
        let header = &self.file.header;
        let slot = header
            .slots
            .iter()
            .find(|s| s.id == slot_id)
            .ok_or_else(|| no_such_slot(slot_id))?;
        let kek = crypto::kek_from_bytes(kek)?;
        let aad = slot_aad(header.format_version, header.vault_id, slot.id, slot.kind);
        let vault_key = crypto::unwrap_key(&kek, &slot.nonce, &aad, &slot.wrapped_key)
            .ok_or(VaultError::WrongPassword)?;
        self.unlock_with_vault_key(vault_key, false)
    }

    /// Unlock with an already-verified `vault_key` exported from a live [`UnlockedVault`] of
    /// the *same* vault, skipping every key slot and therefore Argon2. For `vault-sync` only
    /// (03 §3 step 6a): the watcher unlocks the on-disk copy with the cached key to merge it.
    ///
    /// Item and manifest verification is the same shared path as [`LockedVault::unlock`]
    /// (items in file order, then the manifest), with one difference in error mapping. No
    /// slot is unwrapped here, so nothing checks the key before item decryption; a wrong key
    /// would fail every tag and surface as `Tampered`, which is misleading. Interpretation:
    /// the **first** tag check (the first item record, or the manifest when the vault has no
    /// items) failing is reported as [`VaultError::WrongPassword`], meaning "wrong vault
    /// key". Every later failure is a real [`VaultError::Tampered`], because the key has by
    /// then authenticated at least one record under this vault's `vault_id`. The one case
    /// this conflates is a correct key with a tampered *first* record (or tampered manifest
    /// of an empty vault): it is reported as `WrongPassword`; `unlock` with the password
    /// still reports it as `Tampered`. Likewise a file whose item records were all dropped
    /// (rolled back to empty, with the manifest left behind) fails its first and only tag
    /// check on the manifest and maps to `WrongPassword`.
    ///
    /// Consequently `vault-sync` must treat `WrongPassword` from this method as "re-verify
    /// this file with the password" (prompt, then `unlock`), **never** as "adopt the on-disk
    /// copy silently" and never as proof of corruption.
    ///
    /// Structural errors (`Malformed`, `UnsupportedVersion`) are unchanged.
    ///
    /// The returned vault has `device_id == device_id`.
    #[cfg(feature = "sync")]
    pub fn unlock_with_key(
        &self,
        key: &VaultKeyHandle,
        device_id: Uuid,
    ) -> Result<UnlockedVault, VaultError> {
        let mut vault = self.unlock_with_vault_key(key.0.clone(), true)?;
        vault.device_id = device_id;
        Ok(vault)
    }

    /// Steps 2-4 of the unlock order (module docs). `first_failure_is_wrong_key` is set only
    /// by `unlock_with_key`: the very first AEAD tag failure (first item, or the manifest of
    /// an empty vault) is then reported as `WrongPassword` instead of `Tampered`.
    fn unlock_with_vault_key(
        &self,
        vault_key: crypto::Key32,
        first_failure_is_wrong_key: bool,
    ) -> Result<UnlockedVault, VaultError> {
        let header = &self.file.header;
        let vault_id = header.vault_id;
        let version = header.format_version;
        let keys = Keys::from_vault_key(vault_key, vault_id);

        let mut items = BTreeMap::new();
        let mut record_extras = BTreeMap::new();
        let mut pairs = Vec::with_capacity(self.file.items.len());
        for rec in &self.file.items {
            let aad = item_aad(version, vault_id, rec.id, rec.modified_at);
            let on_fail = tag_failure(
                first_failure_is_wrong_key && pairs.is_empty(),
                TamperKind::Item(rec.id),
            );
            let plain = crypto::open(&keys.item_key, &rec.nonce, &aad, &rec.ct).ok_or(on_fail)?;
            let item = format::decode_item_plain(&plain, rec.id, rec.modified_at)?;
            pairs.push((rec.id, rec.modified_at));
            items.insert(rec.id, item);
            if !rec.extras.is_empty() {
                record_extras.insert(rec.id, rec.extras.clone());
            }
        }

        let item_count = u32::try_from(self.file.items.len())
            .map_err(|_| VaultError::Malformed("more than u32::MAX item records".into()))?;
        let manifest = &self.file.manifest;
        let aad = manifest_aad(version, vault_id, item_count);
        let on_fail = tag_failure(
            first_failure_is_wrong_key && pairs.is_empty(),
            TamperKind::Manifest,
        );
        let plain =
            crypto::open(&keys.manifest_key, &manifest.nonce, &aad, &manifest.ct).ok_or(on_fail)?;
        let expected = format::decode_manifest(&plain)?;
        pairs.sort_unstable();
        if expected != pairs {
            return Err(VaultError::Tampered(TamperKind::Manifest));
        }

        Ok(UnlockedVault {
            header: header.clone(),
            keys,
            device_id: Uuid::nil(),
            items,
            record_extras,
            manifest_extras: manifest.extras.clone(),
        })
    }
}

/// An opaque, zeroizing copy of a vault's 32-byte `vault_key`, for `vault-sync` only (03 §3
/// step 6a). Obtain it with [`UnlockedVault::export_vault_key`], hand it to
/// [`LockedVault::unlock_with_key`], and drop it when the vault locks. **Never persist it**,
/// never log it, never send it across a process boundary. There is deliberately no `Debug`,
/// no `Clone`, no accessor for the bytes: the only things it can do are unlock a `LockedVault`
/// of the same vault and be [`duplicate`](Self::duplicate)d. The bytes are wiped on drop.
#[cfg(feature = "sync")]
pub struct VaultKeyHandle(crypto::Key32);

#[cfg(feature = "sync")]
impl VaultKeyHandle {
    /// Explicit second copy, for a caller that must hold the key in two places (e.g. the
    /// watcher task and the app state). `Clone` is intentionally not implemented so copies
    /// are never made by accident; each copy zeroizes independently on drop.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }
}

/// An open vault: header, key material and decrypted items. `Debug` is implemented manually
/// and prints only the vault id, device id and item count.
pub struct UnlockedVault {
    header: Header,
    keys: Keys,
    device_id: Uuid,
    items: BTreeMap<Uuid, Item>,
    /// Unknown plaintext keys read from each item record, re-emitted on serialize.
    record_extras: BTreeMap<Uuid, Extras>,
    /// Unknown plaintext keys read from the manifest record.
    manifest_extras: Extras,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.header.vault_id)
            .field("device_id", &self.device_id)
            .field(
                "items",
                &format_args!("[{} items redacted]", self.items.len()),
            )
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl UnlockedVault {
    /// Create an empty vault with a fresh random `vault_id` and `vault_key` and one `password`
    /// slot. `created_at` is set to 0 because the core never reads the clock; use
    /// [`UnlockedVault::create_with_created_at`] to record a real timestamp.
    ///
    /// # Panics
    ///
    /// If `kdf` fails [`KdfParams::validate`] or is rejected by Argon2 (e.g.
    /// `m_cost_kib < 8 * p_cost`). The constructors on [`KdfParams`] always produce valid
    /// parameters.
    pub fn create(password: &SecretString, kdf: KdfParams, device_id: Uuid) -> Self {
        Self::create_with_created_at(password, kdf, device_id, 0)
    }

    /// Like [`UnlockedVault::create`], stamping `created_at` (unix seconds) on the header and
    /// the initial slot.
    pub fn create_with_created_at(
        password: &SecretString,
        kdf: KdfParams,
        device_id: Uuid,
        created_at: u64,
    ) -> Self {
        let vault_id = Uuid::new_v4();
        let vault_key = crypto::random_key();
        let kek = crypto::derive_kek(password, &kdf)
            .expect("KdfParams rejected by Argon2; use KdfParams constructors");

        let slot_id = Uuid::new_v4();
        let nonce = crypto::random_nonce();
        let aad = slot_aad(FORMAT_VERSION, vault_id, slot_id, SlotKind::Password);
        let wrapped_key = crypto::wrap_key(&kek, &nonce, &aad, &vault_key);
        let slot = KeySlot {
            id: slot_id,
            kind: SlotKind::Password,
            nonce,
            wrapped_key,
            created_at,
            extras: Vec::new(),
        };

        Self {
            header: Header {
                format_version: FORMAT_VERSION,
                vault_id,
                created_at,
                kdf,
                kdf_extras: Vec::new(),
                slots: vec![slot],
                extras: Vec::new(),
            },
            keys: Keys::from_vault_key(vault_key, vault_id),
            device_id,
            items: BTreeMap::new(),
            record_extras: BTreeMap::new(),
            manifest_extras: Vec::new(),
        }
    }

    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// Set the device id stamped on subsequent mutations (needed after `unlock`).
    pub fn set_device_id(&mut self, device_id: Uuid) {
        self.device_id = device_id;
    }

    /// Export the raw `vault_key` as an opaque [`VaultKeyHandle`] so `vault-sync` can unlock
    /// an on-disk copy of this same vault without re-running Argon2 (03 §3 step 6a). This is
    /// the only way the vault key leaves the core. Never persist the handle; drop it when the
    /// vault locks. Not meaningful across [`UnlockedVault::rotate_vault_key`]: a handle
    /// exported before rotation only opens files written before it.
    #[cfg(feature = "sync")]
    #[must_use]
    pub fn export_vault_key(&self) -> VaultKeyHandle {
        VaultKeyHandle(self.keys.vault_key.clone())
    }

    /// The plaintext header (no secrets).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Mutable access to the header's unknown-key extras, e.g. for forward-compat tests.
    pub fn header_extras_mut(&mut self) -> &mut Extras {
        &mut self.header.extras
    }

    /// Live items (tombstones excluded), in id order.
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.items.values().filter(|i| !i.is_deleted())
    }

    /// Every item including tombstones, in id order.
    pub fn items_including_deleted(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
    }

    /// Look up by id; returns tombstones too.
    pub fn get(&self, id: Uuid) -> Option<&Item> {
        self.items.get(&id)
    }

    /// Insert (or replace, if the id already exists) an item, restamping it like every other
    /// mutation: `modified_at = max(item.modified_at, fields, deleted_at, now)` and
    /// `device_id = self.device_id`. Replacing an existing id additionally requires
    /// `modified_at > existing.modified_at` (never rolls back, always strictly advances) and
    /// drops the old record's unknown plaintext extras, since the new body is not the record
    /// they came with.
    ///
    /// Field names are expected to be unique within an item (01 §4) but this is not enforced:
    /// duplicates are tolerated and written as-is; `Item::field`, `set_field`, `update`'s
    /// diffing and the merge all use the first field with a given name.
    pub fn insert(&mut self, mut item: Item, now: Millis) -> Uuid {
        let id = item.id;
        let mut floor = now;
        if let Some(existing) = self.items.get(&id) {
            floor = floor.max(existing.modified_at.saturating_add(1));
            self.record_extras.remove(&id);
        }
        restamp(&mut item, floor, self.device_id);
        self.items.insert(id, item);
        id
    }

    /// Edit an item in place through `f`, then restamp it (02 "update"):
    ///
    /// - A field (matched by `name` against the pre-call copy) whose `value`, `kind` or
    ///   `section` changed while `f` left its `modified_at` untouched is bumped to
    ///   `stamp(now, previous field modified_at)`. A field whose name is not in the pre-call
    ///   copy counts as new: it gets `stamp(carried if non-zero else now, previous item
    ///   modified_at)`.
    /// - `item.modified_at = max(stamp(now, previous), all field.modified_at, deleted_at)`.
    ///
    /// where `stamp(now, prev) = max(now, prev + 1)` (see [`stamp`]). The spec formula is
    /// `max(fields, deleted_at, now)`; the strictly-advancing floor is added so a mutation
    /// made under clock skew (`now <= prev`) still beats the untouched peer copy it was made
    /// from in a merge, instead of tying on `(modified_at, device_id)` and losing.
    /// - `item.device_id = self.device_id`.
    ///
    /// `f` may change `id`; the change is ignored (the item stays under `id`). Duplicate
    /// field names are tolerated, not deduplicated; the diff matches each post-call field
    /// against the *first* pre-call field with the same name.
    ///
    /// # Errors
    ///
    /// `Malformed("unknown item ..")` if `id` is not in the vault (the error enum has no
    /// dedicated variant yet).
    pub fn update<F: FnOnce(&mut Item)>(
        &mut self,
        id: Uuid,
        now: Millis,
        f: F,
    ) -> Result<(), VaultError> {
        let device_id = self.device_id;
        let item = self.items.get_mut(&id).ok_or_else(|| unknown_item(id))?;
        let before = item.clone();
        f(item);
        item.id = id;
        for field in &mut item.fields {
            match before.fields.iter().find(|b| b.name == field.name) {
                Some(prev) => {
                    if field.modified_at == prev.modified_at
                        && !merge::field_content_eq(field, prev)
                    {
                        field.modified_at = stamp(now, prev.modified_at);
                    }
                }
                None => {
                    let carried = if field.modified_at == 0 {
                        now
                    } else {
                        field.modified_at
                    };
                    field.modified_at = stamp(carried, before.modified_at);
                }
            }
        }
        restamp(item, stamp(now, before.modified_at), device_id);
        Ok(())
    }

    /// Replace the value of an existing field and stamp it `stamp(now, field.modified_at)`
    /// (strictly advancing, see [`stamp`]). For a [`FieldKind::Password`] field the previous value is
    /// pushed onto `history` as `(value, replaced_at = that stamp)`; history is kept
    /// newest-first and capped at [`HISTORY_CAP`]. The item is restamped as in
    /// [`UnlockedVault::update`].
    ///
    /// # Errors
    ///
    /// `Malformed("unknown item ..")` / `Malformed("unknown field ..")`; a missing field is not
    /// created (interpretation: callers add fields through `update`).
    pub fn set_field(
        &mut self,
        id: Uuid,
        name: &str,
        value: SecretString,
        now: Millis,
    ) -> Result<(), VaultError> {
        let device_id = self.device_id;
        let item = self.items.get_mut(&id).ok_or_else(|| unknown_item(id))?;
        let item_floor = stamp(now, item.modified_at);
        let field = item
            .fields
            .iter_mut()
            .find(|f| f.name == name)
            .ok_or_else(|| unknown_field(id, name))?;
        let previous = std::mem::replace(&mut field.value, value);
        let at = stamp(now, field.modified_at);
        field.modified_at = at;
        if field.kind == FieldKind::Password {
            item.history.push(HistoryEntry {
                value: previous,
                replaced_at: at,
            });
            merge::normalize_history(&mut item.history);
        }
        restamp(item, item_floor, device_id);
        Ok(())
    }

    /// Turn an item into a tombstone: `deleted_at = modified_at = stamp(now, modified_at)`
    /// (see [`stamp`]), `device_id = self.device_id`. The floor matters: a `deleted_at` behind
    /// the item's own `modified_at` would lose the merge tombstone rule
    /// (`deleted_at >= other.modified_at`) to any peer's untouched copy and silently undo the
    /// delete under clock skew. Fields and history are left in place (01 §4 only says they
    /// *may* be empty). Deleting a tombstone again moves `deleted_at` forward.
    ///
    /// # Errors
    ///
    /// `Malformed("unknown item ..")` if `id` is not in the vault.
    pub fn delete(&mut self, id: Uuid, now: Millis) -> Result<(), VaultError> {
        let device_id = self.device_id;
        let item = self.items.get_mut(&id).ok_or_else(|| unknown_item(id))?;
        let at = stamp(now, item.modified_at);
        item.deleted_at = Some(at);
        restamp(item, at, device_id);
        Ok(())
    }

    /// Drop every tombstone with `deleted_at < cutoff` (strictly older). Returns how many were
    /// removed. Live items are never touched.
    ///
    /// **Choose `cutoff` conservatively.** A tombstone is the only thing that stops a peer's
    /// stale *live* copy from coming back: once it is purged, a merge from a device that has
    /// been offline since before the delete re-adds the item (`absent -> take theirs`).
    /// `cutoff` must therefore be older than the longest expected offline window plus clock
    /// skew, and `vault-sync` should purge only after a successful merge of every known peer
    /// copy, never on unlock.
    pub fn purge_tombstones_older_than(&mut self, cutoff: Millis) -> usize {
        let before = self.items.len();
        self.items
            .retain(|_, item| !matches!(item.deleted_at, Some(d) if d < cutoff));
        self.record_extras
            .retain(|id, _| self.items.contains_key(id));
        before - self.items.len()
    }

    /// Plaintext `(id, kind)` of every key slot, in header order.
    pub fn slots(&self) -> impl Iterator<Item = (Uuid, SlotKind)> + '_ {
        self.header.slots.iter().map(|s| (s.id, s.kind))
    }

    /// Derive the KEK for `password` under the header's current KDF params and prove it
    /// unwraps at least one `password` slot. Returns that KEK so the caller can re-wrap under
    /// it. The AEAD tag is the only check; the unwrapped bytes are not compared to anything.
    ///
    /// # Errors
    ///
    /// `WrongPassword` if no password slot unwraps; `Malformed` if the header's KDF params
    /// are unusable (cannot happen for a vault this crate produced).
    fn verify_password(&self, password: &SecretString) -> Result<crypto::Key32, VaultError> {
        let header = &self.header;
        let kek = crypto::derive_kek(password, &header.kdf)?;
        // The unwrapped key is dropped (zeroized) unused; only the tag check matters here.
        unwrap_any_password_slot(header, &kek)
            .map(|_| kek)
            .ok_or(VaultError::WrongPassword)
    }

    /// Change the master password (01 §3): verify `old`, derive a new KEK from `new` under
    /// `kdf`, and replace every `password` slot with a fresh one (new id, nonce and
    /// `wrapped_key`) wrapping the *unchanged* `vault_key`. `kdf` becomes the header's KDF
    /// params; because those are header-wide (01 §2) every password slot has to be re-wrapped,
    /// not just the one `old` matched. Consequently, if the header holds several password
    /// slots (allowed by the format, not exposed by the v1 UI), all of them end up wrapped
    /// under `new`, and any other password that previously opened the vault stops working. Each replacement keeps its predecessor's `created_at`
    /// and unknown extras (the core has no clock, and 01 §9 says writers preserve unknown
    /// keys). `enclave` and `recovery` slots are untouched: their KEKs are not
    /// password-derived. Items are untouched in memory and re-encrypted with fresh nonces on
    /// the next `serialize` (guarantee 8).
    ///
    /// # Errors
    ///
    /// `WrongPassword` if `old` unwraps no password slot; `Malformed` if `kdf` fails
    /// [`KdfParams::validate`] or is rejected by Argon2. On either error the header is left
    /// exactly as it was.
    pub fn change_password(
        &mut self,
        old: &SecretString,
        new: &SecretString,
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        self.verify_password(old)?;
        let new_kek = crypto::derive_kek(new, &kdf)?;
        let version = self.header.format_version;
        let vault_id = self.header.vault_id;
        for slot in &mut self.header.slots {
            if slot.kind != SlotKind::Password {
                continue;
            }
            let mut fresh = new_slot(
                version,
                vault_id,
                SlotKind::Password,
                &new_kek,
                &self.keys.vault_key,
                slot.created_at,
            );
            fresh.extras = std::mem::take(&mut slot.extras);
            *slot = fresh;
        }
        self.header.kdf = kdf;
        Ok(())
    }

    /// Add an `enclave` slot wrapping the current `vault_key` under a caller-held 32-byte KEK
    /// (01 §2; phase 4 stores that KEK in the Keychain behind Touch ID). Returns the new slot's
    /// id, which the caller must keep to call [`LockedVault::unlock_with_kek`] later. The
    /// slot's `created_at` is 0 because the core never reads the clock; use
    /// [`UnlockedVault::add_enclave_slot_with_created_at`] to record a real timestamp.
    ///
    /// # Panics
    ///
    /// If `kek` is not exactly 32 bytes. The signature (02) has no error channel, and a
    /// mis-sized KEK is a caller bug, not a runtime condition: the caller generated it.
    pub fn add_enclave_slot(&mut self, kek: &SecretVec<u8>) -> Uuid {
        self.add_enclave_slot_with_created_at(kek, 0)
    }

    /// Like [`UnlockedVault::add_enclave_slot`], stamping `created_at` (unix seconds).
    ///
    /// # Panics
    ///
    /// If `kek` is not exactly 32 bytes.
    pub fn add_enclave_slot_with_created_at(
        &mut self,
        kek: &SecretVec<u8>,
        created_at: u64,
    ) -> Uuid {
        let kek = crypto::kek_from_bytes(kek).expect("enclave KEK must be exactly 32 bytes");
        let slot = new_slot(
            self.header.format_version,
            self.header.vault_id,
            SlotKind::Enclave,
            &kek,
            &self.keys.vault_key,
            created_at,
        );
        let id = slot.id;
        self.header.slots.push(slot);
        id
    }

    /// Remove a key slot by id. Refuses to remove the only `password` slot, since the vault
    /// would then be openable only through Keychain-held material, and refuses to remove the
    /// last slot of any kind, since the parser requires at least one (01 §2). The second guard
    /// is unreachable through this API today (the password-slot guard fires first) and exists
    /// so a future constructor cannot produce an unparseable header.
    ///
    /// # Errors
    ///
    /// `Malformed("no such slot ..")` if `id` is not in the header;
    /// `Malformed("cannot remove last password slot")` / `Malformed("cannot remove last
    /// slot")` when refused.
    pub fn remove_slot(&mut self, id: Uuid) -> Result<(), VaultError> {
        let slots = &mut self.header.slots;
        let index = slots
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| no_such_slot(id))?;
        let password_slots = slots
            .iter()
            .filter(|s| s.kind == SlotKind::Password)
            .count();
        if slots[index].kind == SlotKind::Password && password_slots == 1 {
            return Err(VaultError::Malformed(
                "cannot remove last password slot".into(),
            ));
        }
        if slots.len() == 1 {
            return Err(VaultError::Malformed("cannot remove last slot".into()));
        }
        slots.remove(index);
        Ok(())
    }

    /// Replace `vault_key` with a fresh random key (01 §3 "rotating `vault_key` itself"):
    /// verify `password`, generate the new key from `OsRng`, and re-wrap it (fresh nonce, same
    /// slot id and `created_at`) into every `password` slot under the KEK derived from
    /// `password` with the current header params. Every item and the manifest are encrypted
    /// under the new key on the next `serialize`, since their keys derive from `vault_key`.
    /// The old key material is zeroized when dropped.
    ///
    /// **`enclave` (and reserved `recovery`) slots are dropped.** Their KEKs are not derivable
    /// from the password, so the core cannot re-wrap the new key into them; keeping them would
    /// leave slots that silently fail to unlock. Callers must re-enroll Touch ID
    /// ([`UnlockedVault::add_enclave_slot`]) after a rotation. Interpretation: the 02
    /// signature returns `()`, so the dropped ids are not reported; read
    /// [`UnlockedVault::slots`] before and after if you need them. Phase 4 must therefore
    /// treat `Malformed("no such slot ..")` from [`LockedVault::unlock_with_kek`] as "the
    /// enrolment is stale: re-enroll Touch ID", not as a corrupt file.
    ///
    /// Bytes already written are not affected: an earlier `serialize` output remains a valid,
    /// independent vault under the old password and old enclave KEKs.
    ///
    /// # Errors
    ///
    /// `WrongPassword` if `password` unwraps no password slot. The vault is then unchanged.
    pub fn rotate_vault_key(&mut self, password: &SecretString) -> Result<(), VaultError> {
        let kek = self.verify_password(password)?;
        let new_key = crypto::random_key();
        let version = self.header.format_version;
        let vault_id = self.header.vault_id;
        self.header.slots.retain(|s| s.kind == SlotKind::Password);
        for slot in &mut self.header.slots {
            let nonce = crypto::random_nonce();
            let aad = slot_aad(version, vault_id, slot.id, slot.kind);
            slot.wrapped_key = crypto::wrap_key(&kek, &nonce, &aad, &new_key);
            slot.nonce = nonce;
        }
        // Dropping the previous `Keys` zeroizes the old vault key and its subkeys.
        self.keys = Keys::from_vault_key(new_key, vault_id);
        Ok(())
    }

    /// Encrypt every item (id order) and the manifest with fresh nonces and emit the file.
    /// Slots are written as stored. Never fails.
    pub fn serialize(&self) -> Vec<u8> {
        let vault_id = self.header.vault_id;
        let version = self.header.format_version;
        let mut records = Vec::with_capacity(self.items.len());
        let mut pairs = Vec::with_capacity(self.items.len());
        for (id, item) in &self.items {
            let plain = format::encode_item_plain(item);
            let nonce = crypto::random_nonce();
            let aad = item_aad(version, vault_id, *id, item.modified_at);
            let ct = crypto::seal(&self.keys.item_key, &nonce, &aad, &plain);
            records.push(ItemRecord {
                id: *id,
                modified_at: item.modified_at,
                nonce,
                ct,
                extras: self.record_extras.get(id).cloned().unwrap_or_default(),
            });
            pairs.push((*id, item.modified_at));
        }

        // BTreeMap iteration is already sorted by id (Uuid orders by bytes).
        let item_count = u32::try_from(records.len()).expect("more than u32::MAX items");
        let nonce = crypto::random_nonce();
        let aad = manifest_aad(version, vault_id, item_count);
        let ct = crypto::seal(
            &self.keys.manifest_key,
            &nonce,
            &aad,
            &format::encode_manifest(&pairs),
        );
        let manifest = ManifestRecord {
            nonce,
            ct,
            extras: self.manifest_extras.clone(),
        };

        VaultFile {
            header: self.header.clone(),
            items: records,
            manifest,
        }
        .to_bytes()
    }
}

/// The timestamp a local mutation gets: `max(now, previous + 1)`. Every mutation therefore
/// strictly advances the timestamp it replaces, even when the caller's clock is behind, so
/// the edit beats the untouched copy it was made from in a merge instead of tying.
fn stamp(now: Millis, previous: Millis) -> Millis {
    now.max(previous.saturating_add(1))
}

/// Recompute `item.modified_at = max(item.modified_at, floor, all field.modified_at,
/// deleted_at)` and stamp `device_id`. `floor` is the smallest acceptable value (callers pass
/// `stamp(now, previous)`). Shared by every mutation so the record timestamp (which is bound
/// into the item AAD and the manifest) is always the newest timestamp inside the item.
fn restamp(item: &mut Item, floor: Millis, device_id: Uuid) {
    let mut latest = item.modified_at.max(floor);
    for field in &item.fields {
        latest = latest.max(field.modified_at);
    }
    if let Some(deleted_at) = item.deleted_at {
        latest = latest.max(deleted_at);
    }
    item.modified_at = latest;
    item.device_id = device_id;
}
