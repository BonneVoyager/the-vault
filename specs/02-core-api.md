# 02 — `vault-core` public API

Pure library. No I/O, no async, no platform crates, no globals. `#![forbid(unsafe_code)]`.

Dependencies (all RustCrypto / well-known): `argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `rand` (`OsRng` only), `zeroize`, `secrecy`, `ciborium`, `serde`, `uuid` (v4, serde), `totp-rs`, `unicode-normalization`, `thiserror`. Nothing else without a reason in the PR.

## Module layout

```
vault_core
├── format      parse / serialize bytes ↔ structs       (01-vault-format.md)
├── crypto      kdf, wrap/unwrap, aead helpers, hkdf    (private, re-exported minimally)
├── vault       LockedVault, UnlockedVault              (the main API)
├── item        Item, Field, FieldKind, ItemKind, builders
├── merge       three-way-free LWW merge               (03-sync.md §5)
├── totp        parse otpauth://, generate codes
├── generator   password / passphrase generator
├── search      in-memory ranking over unlocked items
├── import      csv, 1pux, kdbx (feature-gated)
├── export      csv (plaintext, with loud warning type)
└── error       VaultError
```

## Core types

```rust
pub struct LockedVault { /* parsed header + raw records, no keys */ }
pub struct UnlockedVault { /* header, vault_key (Zeroizing), items: BTreeMap<Uuid, Item>, extras */ }

pub struct Item {
    pub id: Uuid,
    pub kind: ItemKind,          // Copy; `Other` for a kind string this version does not know
    pub kind_raw: Option<String>,// the on-disk string when kind == Other, else None; `kind_str()` returns the on-disk string
    pub title: String,
    pub deleted_at: Option<Millis>,
    pub device_id: Uuid,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub fields: Vec<Field>,
    pub history: Vec<HistoryEntry>,
    pub modified_at: Millis,
}

pub struct Field {
    pub name: String,
    pub kind: FieldKind,         // Copy; `Other` for unknown; `is_sensitive()` = Password | Totp | Other
    pub kind_raw: Option<String>,// as on Item
    pub value: SecretString,     // secrecy; Display is redacted
    pub modified_at: Millis,
    pub section: Option<String>,
}

pub type Millis = u64;
```

`Item` is `Clone` but not `Debug` by derive — implement `Debug` manually and redact `fields`.

## `LockedVault`

```rust
impl LockedVault {
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError>;
    pub fn vault_id(&self) -> Uuid;
    pub fn kdf_params(&self) -> &KdfParams;
    pub fn item_summaries(&self) -> impl Iterator<Item = (Uuid, Millis)>;   // plaintext metadata only
    pub fn unlock(&self, password: &SecretString) -> Result<UnlockedVault, VaultError>;
    pub fn unlock_with_kek(&self, slot_id: Uuid, kek: &SecretVec<u8>) -> Result<UnlockedVault, VaultError>; // enclave or passkey slot
    #[cfg(feature = "sync")]
    pub fn unlock_with_key(&self, key: &VaultKeyHandle) -> Result<UnlockedVault, VaultError>;             // vault-sync only; first tag failure → WrongPassword
}
```

`unlock` tries every `password` slot. Argon2 runs once per slot; with one slot that's the only cost.

## `UnlockedVault`

```rust
impl UnlockedVault {
    pub fn create(password: &SecretString, kdf: KdfParams, device_id: Uuid) -> Self;

    // read
    pub fn vault_id(&self) -> Uuid;
    pub fn items(&self) -> impl Iterator<Item = &Item>;              // excludes tombstones
    pub fn items_including_deleted(&self) -> impl Iterator<Item = &Item>;
    pub fn get(&self, id: Uuid) -> Option<&Item>;

    // write — every mutation stamps modified_at = now and device_id = self.device_id
    pub fn insert(&mut self, item: Item, now: Millis) -> Uuid;
    pub fn update<F: FnOnce(&mut Item)>(&mut self, id: Uuid, now: Millis, f: F) -> Result<(), VaultError>;
    pub fn set_field(&mut self, id: Uuid, name: &str, value: SecretString, now: Millis) -> Result<(), VaultError>;
    pub fn delete(&mut self, id: Uuid, now: Millis) -> Result<(), VaultError>;    // tombstone, keeps id
    pub fn purge_tombstones_older_than(&mut self, cutoff: Millis) -> usize;

    // keys
    pub fn change_password(&mut self, old: &SecretString, new: &SecretString, kdf: KdfParams) -> Result<(), VaultError>;
    pub fn add_enclave_slot(&mut self, kek: &SecretVec<u8>) -> Uuid;
    pub fn add_passkey_slot(&mut self, kek: &SecretVec<u8>, credential_id: Vec<u8>, prf_salt: [u8; 32], rp_id: String) -> Uuid; // 01 §2; not yet implemented
    pub fn remove_slot(&mut self, id: Uuid) -> Result<(), VaultError>;   // refuses to remove last password slot
    pub fn rotate_vault_key(&mut self, password: &SecretString) -> Result<(), VaultError>;

    // merge (03-sync.md)
    pub fn merge_from(&mut self, other: &UnlockedVault) -> MergeReport;

    // out
    pub fn serialize(&self) -> Vec<u8>;    // fresh nonces every call; never fails
    pub fn device_id(&self) -> Uuid;
}

pub struct MergeReport { pub added: usize, pub updated: usize, pub deleted: usize, pub unchanged: usize }
```

`now` is always passed in — the core never calls the clock. Tests pass fixed values.

`set_field` on a `password`-kind field pushes the previous value onto `history` (cap 10).

`update` recomputes `item.modified_at = max(all field.modified_at, deleted_at, now)` after `f` runs. If `f` changed a field's value without bumping that field's `modified_at`, `update` bumps it to `now` by diffing against the pre-call copy. This keeps field timestamps honest without making every caller remember.

## `kdf`

```rust
pub struct KdfParams { pub m_cost_kib: u32, pub t_cost: u32, pub p_cost: u32, pub salt: [u8; 32] }
impl KdfParams {
    pub fn recommended() -> Self;                       // 64 MiB / 3 / 4, random salt
    pub fn calibrate(target: Duration) -> Self;         // see 01 §6
    pub fn for_tests() -> Self;                         // 8 MiB / 1 / 1
}
```

## `totp`

```rust
pub struct Totp { /* parsed otpauth */ }
impl Totp {
    pub fn parse_uri(uri: &str) -> Result<Self, TotpError>;      // otpauth://totp/...  (hotp rejected); scheme/host case-insensitive, secret normalised (case, padding, spaces, dashes), no minimum secret length
    pub fn from_secret_base32(secret: &str) -> Result<Self, TotpError>;  // defaults SHA1/6/30
    pub fn code(&self, unix_secs: u64) -> String;
    pub fn seconds_remaining(&self, unix_secs: u64) -> u32;
    pub fn period(&self) -> u32;
    pub fn to_uri(&self) -> SecretString;
}
```

Supports SHA1/SHA256/SHA512, 6/7/8 digits, any period. Steam-style codes are out of scope.

## `generator`

```rust
pub struct PasswordSpec { pub length: usize, pub lower: bool, pub upper: bool, pub digits: bool, pub symbols: bool, pub exclude_ambiguous: bool }
pub struct PassphraseSpec { pub words: usize, pub separator: char, pub capitalize: bool, pub number: bool }
pub fn password(spec: &PasswordSpec) -> SecretString;    // guarantees ≥1 char from each enabled class
pub fn passphrase(spec: &PassphraseSpec) -> SecretString; // EFF large wordlist, bundled via include_str!
pub fn strength_bits(pw: &str) -> f64;                    // naive entropy estimate for the UI meter
```

Defaults: password 20 chars, all classes, exclude ambiguous. Passphrase 4 words, `-`, capitalize, number.

## `search`

```rust
pub struct Query<'a> { pub text: &'a str, pub kind: Option<ItemKind>, pub tag: Option<&'a str>, pub favorites_only: bool }
pub fn search<'a>(vault: &'a UnlockedVault, q: &Query) -> Vec<&'a Item>;   // ranked
```

Ranking: title prefix match > title substring > url host match > username match > tag match > notes substring. Case-insensitive, Unicode-folded. Stable sort by `title` within rank. Simple, no fuzzy library in v1.

## `import` / `export`

```rust
pub fn import_csv(bytes: &[u8], mapping: &CsvMapping, device_id: Uuid, now: Millis) -> Result<Vec<Item>, ImportError>;
pub fn import_1pux(bytes: &[u8], device_id: Uuid, now: Millis) -> Result<Vec<Item>, ImportError>;        // zip + JSON
#[cfg(feature = "kdbx")] pub fn import_kdbx(bytes: &[u8], password: &SecretString) -> Result<Vec<Item>, ImportError>;

pub struct PlaintextExport(pub Vec<u8>);   // newtype so callers can't confuse it with vault bytes
pub fn export_csv(vault: &UnlockedVault) -> PlaintextExport;
```

Imported items get fresh ids, `modified_at = now` supplied by caller, `device_id` of the importer.

## Behavioural guarantees (write tests for each)

1. `parse(serialize(v)).unlock(pw) == v` for any `v` (item-wise equality, nonces differ).
2. Two `serialize()` calls produce different bytes (nonces) but equal items.
3. `unlock` with wrong password → `WrongPassword`, and timing does not depend on which byte is wrong (no early-exit comparisons; AEAD does this for us — just don't add your own).
4. Flipping any byte in any item `ct` → `Tampered(Item(id))`.
5. Removing an item record → `Tampered(Manifest)`.
6. Replacing an item record with the same item's record from an older serialize → `Tampered(Manifest)`.
7. Moving an item record into a different vault file → `Tampered(Item(id))`.
8. `change_password` leaves item ciphertexts... actually re-serialized with fresh nonces, but `vault_key` unchanged — verify by unlocking with an `enclave` slot added before the change.
9. `delete` then `merge_from` an older copy that still has the item → item stays deleted.
10. `generator::password` with `symbols: true, length: 4` still contains one of each enabled class.
