# 02 — `vault-core` public API

Pure library. No I/O, no async, no platform crates, no globals (one exception: `generator.rs` keeps the parsed EFF wordlist in a `static` `OnceLock` cache; it holds no secrets and no state that affects results). (spec aligned to code 2026-11-19) `#![forbid(unsafe_code)]`.

Dependencies (all RustCrypto / well-known): `argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `rand` (`OsRng` only), `zeroize`, `secrecy`, `ciborium`, `serde`, `uuid` (v4, serde), `totp-rs`, `unicode-normalization`, `thiserror`, `csv`, `zip`, `serde_json`, `zxcvbn` (plus the optional `keepass` behind the `kdbx` feature). Nothing else without a reason in the PR.

## Module layout

```
vault_core
├── format      parse / serialize bytes ↔ structs       (01-vault-format.md)
├── crypto      kdf, wrap/unwrap, aead helpers, hkdf    (private, re-exported minimally)
├── vault       LockedVault, UnlockedVault              (the main API)
├── item        Item, Field, FieldKind, builders
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
    // no `kind`: categories were removed on 2026-10-30; templates add a tag (#login, #note, #card, #identity) instead
    pub title: String,
    pub deleted_at: Option<Millis>,
    pub device_id: Uuid,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub icon: Option<ItemIcon>,  // v1.2; app-interpreted, set through `update` (which restamps)
    pub created_at: Option<Millis>,  // v1.3; Item::new sets Some(now); merge keeps the minimum; not part of "changed"
    pub title_modified_at: Option<Millis>,      // per-attribute stamps (01 §4, 2026-10-31); None reads as modified_at
    pub favorite_modified_at: Option<Millis>,
    pub tags_modified_at: Option<Millis>,
    pub icon_modified_at: Option<Millis>,
    pub fields: Vec<Field>,
    pub history: Vec<HistoryEntry>,   // HistoryEntry { value, replaced_at, field_id: Option<Uuid> }; no extras
    pub attachments: Vec<AttachmentRef>,   // v1.1; sorted by (added_at, id)
    pub removed_attachments: Vec<AttachmentTombstone>,   // AttachmentTombstone { id, removed_at }; no extras
    pub removed_history: Vec<Millis>,   // replaced_at stamps of deleted history entries (01 §4)
    pub removed_fields: Vec<FieldTombstone>,   // FieldTombstone { id, removed_at }; no extras; 03 §5
    pub extras: Extras,   // unknown ItemPlain keys, preserved (01 §9)
    pub modified_at: Millis,
}

pub struct ItemIcon { pub kind: String, pub value: String, pub color: Option<String>, pub extras: Extras }   // Clone, PartialEq, Debug; nothing secret; 01 §4

pub struct Field {
    pub id: Uuid,                // stable identity (2026-10-31); random v4 from Field::new; derived for version 1 files (01 §9)
    pub name: String,            // a label: not unique within an item, may be empty
    pub kind: FieldKind,         // Copy; `Other` for unknown; `is_sensitive()` = Password | Pin | Totp | Other (Section is never sensitive); ALL has 10 entries incl. Pin (2026-11-15) and Section
    pub kind_raw: Option<String>,// as on Item
    pub value: SecretString,     // secrecy; Display is redacted
    pub modified_at: Millis,
    pub section: Option<String>,
    pub icon: Option<String>,    // 2026-11-07; app-interpreted symbol name (01 §4; any identifier of the bundled Lucide catalog since 2026-11-16, e.g. "KeyRound"); nothing secret; None when absent; Field::new sets None
    pub extras: Extras,          // unknown field keys, preserved (01 §9)
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
    pub fn unlock_with_key(&self, key: &VaultKeyHandle, device_id: Uuid) -> Result<UnlockedVault, VaultError>;  // vault-sync only. A tag failure before any record authenticates is settled by opening the manifest with the same key: Tampered(Item(id)) if it opens, WrongPassword if not; a vault with no items reports a failing manifest as WrongPassword (nothing to probe). After one record authenticates every failure is Tampered. Guarantee 4 holds on this path (bug hunt 2026-11-21 L1)
}
```

`unlock` tries every `password` slot. Argon2 runs once per unlock: the KEK is derived once and tried against every `password` slot, so extra slots cost only an AEAD unwrap each. (spec aligned to code 2026-11-19)

## `UnlockedVault`

```rust
impl UnlockedVault {
    pub fn create(password: &SecretString, kdf: KdfParams, device_id: Uuid) -> Self;

    // read
    pub fn vault_id(&self) -> Uuid;
    pub fn items(&self) -> impl Iterator<Item = &Item>;              // excludes tombstones
    pub fn items_including_deleted(&self) -> impl Iterator<Item = &Item>;
    pub fn get(&self, id: Uuid) -> Option<&Item>;

    // write — every mutation stamps modified_at = `max(now, previous + 1)` (strictly advancing, so a skewed clock still beats the copy it edited) and device_id = self.device_id (spec aligned to code 2026-11-19)
    pub fn insert(&mut self, item: Item, now: Millis) -> Uuid;
    pub fn update<F: FnOnce(&mut Item)>(&mut self, id: Uuid, now: Millis, f: F) -> Result<(), VaultError>;
    pub fn set_field(&mut self, id: Uuid, field_id: Uuid, value: SecretString, now: Millis) -> Result<(), VaultError>;        // by field id (2026-10-31)
    pub fn set_field_named(&mut self, id: Uuid, name: &str, value: SecretString, now: Millis) -> Result<(), VaultError>;  // first non-Section field matching the name ASCII case-insensitively; FieldNotFound / AmbiguousField
    pub fn remove_field(&mut self, id: Uuid, field_id: Uuid, now: Millis) -> Result<(), VaultError>;   // writes a removed_fields marker
    pub fn upgrade_format(&mut self, password: &SecretString, now: Millis) -> Result<(), VaultError>;   // version 1 → 2; drops non-password slots (01 §9); no-op when current
    pub fn delete(&mut self, id: Uuid, now: Millis) -> Result<(), VaultError>;    // tombstone, keeps id AND content (the item moves to Recently Deleted; 2026-11-03)
    pub fn recover(&mut self, id: Uuid, now: Millis) -> Result<(), VaultError>;   // clears deleted_at on a tombstone that still has content; restamps (03 §5: a later edit resurrects). Err on unknown id, a live item, or a stripped tombstone
    pub fn delete_permanently(&mut self, id: Uuid, now: Millis) -> Result<(), VaultError>; // strips a tombstone (see below) and restamps so it wins the merge; Err on unknown id or a live item
    pub fn expire_deleted(&mut self, cutoff: Millis, now: Millis) -> usize;       // strips every tombstone with content whose deleted_at < cutoff, restamping each; returns how many. Idempotent
    pub fn deleted_items(&self) -> impl Iterator<Item = &Item>;                    // tombstones that still have content (the Recently Deleted list)
    pub fn purge_tombstones_older_than(&mut self, cutoff: Millis) -> usize;

    // keys
    pub fn change_password(&mut self, old: &SecretString, new: &SecretString, kdf: KdfParams, now: Millis) -> Result<(), VaultError>;   // stamps the header (01 §2)
    pub fn add_enclave_slot(&mut self, kek: &SecretVec<u8>, now: Millis) -> Uuid;
    pub fn add_passkey_slot(&mut self, kek: &SecretVec<u8>, credential_id: Vec<u8>, prf_salt: [u8; 32], rp_id: String) -> Uuid; // 01 §2; not implemented; not in the code as of 2026-11-19
    pub fn remove_slot(&mut self, id: Uuid, now: Millis) -> Result<(), VaultError>;   // refuses to remove last password slot
    pub fn rotate_vault_key(&mut self, password: &SecretString, now: Millis) -> Result<(), VaultError>;

    // attachments (01 §4 "Attachments"); refs only — blobs are sealed/opened by `attachment::{seal, open}` and stored by vault-sync
    pub fn add_attachment_ref(&mut self, item: Uuid, r: AttachmentRef, now: Millis) -> Result<(), VaultError>;
    pub fn remove_attachment_ref(&mut self, item: Uuid, id: Uuid, now: Millis) -> Result<(), VaultError>;
    pub fn attachment_ids(&self) -> impl Iterator<Item = Uuid>;     // all items incl. tombstones, for orphan cleanup

    // merge (03-sync.md)
    pub fn merge_from(&mut self, other: &UnlockedVault) -> Result<MergeReport, VaultError>;   // Err on a different vault_id

    // out
    pub fn serialize(&self) -> Vec<u8>;    // fresh nonces every call; never fails
    pub fn device_id(&self) -> Uuid;
}

pub struct MergeReport { pub added: usize, pub updated: usize, pub deleted: usize, pub unchanged: usize, pub header_updated: bool }
```

`now` is always passed in — the core never calls the clock. Tests pass fixed values.

`set_field` on a `password`- or `pin`-kind field (pin since 2026-11-15, owner decision: PINs keep the history disclosure) pushes the previous value onto `history` (cap 10).

`update` recomputes `item.modified_at = max(stamp(now, previous), all field.modified_at, attribute stamps, deleted_at, new markers)` after `f` runs, where `stamp(now, prev) = max(now, prev + 1)`; `recover` and a strip use the same stamp floored past `deleted_at` as well as `modified_at`. (spec aligned to code 2026-11-19) It diffs fields by id against the pre-call copy: a field whose name, kind, value or section changed without a bumped `modified_at` is bumped to `now` (a rename is an edit, not a delete + add); an id that vanished gets a `removed_fields` marker stamped `now`; a re-added id is stamped past its marker and the marker dropped; a duplicate id within an item is rejected and the item restored. `Item::field(name)` returns the first non-Section field whose name matches ASCII case-insensitively (an empty name never matches); `Item::field_by_id(id)` is the identity lookup.

**Recently Deleted (2026-11-03).** `delete` keeps the whole item under its tombstone: fields, history, attachment refs, extras and the removal markers. Such a tombstone is "in the trash". **Stripping** a tombstone empties `fields`, `history`, `attachments`, `removed_fields`, `removed_attachments`, `removed_history` and `extras`, keeps `id`, `title`, `tags`, `favorite`, `icon`, `created_at`, `deleted_at` and the per-attribute stamps, and restamps `modified_at = stamp(now, previous)` with `device_id = self.device_id`, so the stripped version wins the whole-item merge of two tombstones (03 §5) and the content disappears on every device. `Item::has_content()` is true when any of the emptied lists is non-empty. The retention window is the caller's (`vault-app` uses 30 days from `deleted_at`); the core only exposes `expire_deleted(cutoff, now)`. A stripped tombstone is what every tombstone was before 2026-11-03; the format is unchanged (01 §4: fields may be empty on a tombstone) and `FORMAT_VERSION` does not change. `purge_tombstones_older_than` is unchanged and still unused by the app. Trash membership (bug-hunt L1, 2026-11-06): a tombstone is *in the trash* when `Item::is_trashed()`: `deleted_at` is set and the tombstone either still has content or has not been restamped since the delete (`modified_at <= deleted_at`). `delete` leaves `deleted_at == modified_at`; a strip (and a recover) restamps strictly past `max(modified_at, deleted_at)`, which is what removes a content-less (title-only) tombstone from the trash even when a peer crafted `deleted_at` ahead of `modified_at`. `deleted_items`, `recover` (Err on unknown id, a live item, or a tombstone not in the trash), `expire_deleted` and the delete-on-stripped no-op all use `is_trashed`; `has_content` only describes what a strip removes. Known residuals: a same-millisecond cross-device delete tie leaves a title-only tombstone stripped on the merging side (the 03 §5 +1 bump); tombstones written before 2026-11-03 count as trashed until the first sweep. KeePass (bug-hunt L2): key and cipher failures are `KdbxCredentials`; everything the parser rejects after authentication, including block-HMAC mismatches, is `KdbxMalformed`.

## Also exported (2026-11-19, verified against `lib.rs` and the modules; names only)

- `LockedVault`: `header`, `slots`
- `UnlockedVault`: `create_with_created_at`, `set_device_id`, `export_vault_key` (feature `sync`), `header`, `header_extras_mut`, `try_insert`, `remove_history_entry`, `clear_history`, `add_enclave_slot_with_created_at`, `slots`
- `VaultKeyHandle::duplicate` (feature `sync`); `MergeReport::changed`
- `merge`: `merge_items`, `item_eq`
- `vault`: `HISTORY_CAP`, `ATTACHMENT_TOMBSTONE_CAP`, `FIELD_TOMBSTONE_CAP`
- `kdf`: `MAX_T_COST`, `MAX_P_COST`, `MAX_M_COST_KIB`, `KdfParams::validate` (01 §2 range)
- `generator`: `STRENGTH_SCORED_CHARS`, `PasswordSpec::min_length`
- `attachment`: `new_ref`, `validate_ref`, `chunk_count`, `blob_file_name`, `CHUNK_SIZE`, `MAX_ATTACHMENT_SIZE`, `ATTACHMENT_VERSION`, `AttachmentError`
- the `format` module (`Header`, `KeySlot`, `OpaqueSlot`, `Slot`, `SlotKind`, `MAGIC`, `FORMAT_VERSION`)

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
pub fn password(spec: &PasswordSpec) -> SecretString;    // guarantees ≥1 char from each enabled class; `length` is clamped up to `PasswordSpec::min_length()` (the enabled-class count), and with no class enabled it falls back to lowercase (2026-11-19)
pub fn passphrase(spec: &PassphraseSpec) -> SecretString; // EFF large wordlist, bundled via include_str!
pub fn generated_bits(spec: &PasswordSpec) -> f64;        // exact entropy of the generator's own uniform draws: log2(pool) × length (2026-11-17; the UI generator preview uses this, not strength_bits)
pub fn generated_passphrase_bits(spec: &PassphraseSpec) -> f64; // log2(7776) × words (+ log2(10) with the digit)
pub fn strength_bits(pw: &str) -> f64;                    // log2 of the zxcvbn guess estimate for the first 100 characters (0 for empty, at most 64 because zxcvbn caps guesses at 2^64); used by the UI meter, the weak-password audit and the 50-bit master minimum. Replaced the naive pool×length estimate 2026-11-17 (owner decision, strength-meter cliffs). zxcvbn reads the clock (the current year once per process for date patterns, and a monotonic timer per call); these, plus the monotonic `Instant::now()` in `KdfParams::calibrate`, are the only clock reads in vault-core and the accepted exception (spec aligned to code 2026-11-19) to the no-I/O rule; `time` is built without local-offset so no tz or libc lookup; zip 9 pulls `nix`/`libc` into the graph but only its never-called extract paths use them.
```

Defaults: password 20 chars, all classes, exclude ambiguous. Passphrase 4 words, `-`, capitalize, number.

## `search`

```rust
pub struct Query<'a> { pub text: &'a str, pub tag: Option<&'a str>, pub favorites_only: bool }
pub fn search<'a>(vault: &'a UnlockedVault, q: &Query) -> Vec<&'a Item>;   // ranked
```

Ranking: title prefix match > title substring > url host match > username or `Email`-kind field match > tag match > notes substring. Case-insensitive, Unicode-folded. Field-name comparisons in search and export (e.g. the `username` field) are ASCII case-insensitive (2026-10-31), because the app's templates store natural labels such as "Username" while importers and the CLI write lowercase names. Stable sort by `title` within rank. Simple, no fuzzy library in v1.

## `import` / `export`

```rust
pub fn import_csv(bytes: &[u8], mapping: &CsvMapping, device_id: Uuid, now: Millis) -> Result<Vec<Item>, ImportError>;
pub fn import_1pux(bytes: &[u8], device_id: Uuid, now: Millis) -> Result<Vec<Item>, ImportError>;        // zip + JSON
#[cfg(feature = "kdbx")] pub fn import_kdbx(bytes: &[u8], password: &SecretString, keyfile: Option<&[u8]>, device_id: Uuid, now: Millis) -> Result<Vec<Item>, ImportError>;

pub struct PlaintextExport(pub Vec<u8>);   // newtype so callers can't confuse it with vault bytes
pub fn export_csv(vault: &UnlockedVault) -> PlaintextExport;
```

`export_csv` prefixes a `'` to any cell starting with `=`, `+`, `-`, `@`, tab or carriage return (CSV-injection guard; a cell that is already a trigger behind quotes gets one more). `import_csv` strips exactly one leading `'` when a trigger follows it (behind zero or more further quotes), so an export round-trips. (spec aligned to code 2026-11-19)

Imported items get fresh ids, `modified_at = now` supplied by caller, `device_id` of the importer. `created_at` is the source's creation time when it has one (1PUX createdAt seconds, KeePass CreationTime; zero, negative or non-numeric → now), else now; CSV always now.

KeePass import uses the optional `keepass` dependency with its default features disabled. It accepts KDBX 3/4, a password, and optional raw key-file bytes (empty password with a key file means key-file-only authentication). Each entry becomes a login; standard fields map to username/password/website/notes, `otp` to TOTP, and protected custom fields remain concealed. Custom-name collisions receive numeric suffixes. Entry tags and nested group paths are retained as tags; recycle-bin entries are skipped; up to ten password-history values are retained. Attachments, custom icons and auto-type settings are not transferred. Input limits: database 100 MiB, key file 1 MiB; exceeding either is `ImportError::Malformed` (1PUX limits use `TooLarge`). `check_outer_header` also bounds the KDBX KDF before any key derivation: AES-KDF rounds at most 2^26, Argon2 memory at most 1 GiB, iterations at most 64, parallelism at most 16; anything above is rejected. (spec aligned to code 2026-11-19) 1PUX: the app reads archives up to 1 GiB on a background thread (CSV up to 64 MiB; KDBX 100 MiB with a 1 MiB key file); `import_1pux` reads the archive's End of Central Directory record itself before opening it and refuses, with `ImportError::TooLarge`, an archive that declares more than 10 000 entries or a ZIP64 central directory; `export.data` is then bounded at 64 MiB from its declared size before inflation and again while inflating; the archive as a whole is not otherwise bounded by core (bug-hunt M2 + security review, 2026-11-06). Error text never includes dependency parser errors or secret values. The dependency wipes credentials and protected fields; its transient XML and unprotected allocations are not guaranteed to be zeroized, like the existing 1PUX parser.

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
