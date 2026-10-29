//! Bytes <-> structs for the `.vault` file (`01-vault-format.md` §1, §2, §4) and the AAD
//! layouts for every AEAD call in the format.
//!
//! # Canonical CBOR
//!
//! Every map this module writes goes through [`canonicalize`], which recursively sorts map
//! entries by plain bytewise lexicographic order of the *encoded* key (RFC 8949 §4.2.1; this is
//! not the older RFC 7049 length-first rule).
//! `ciborium` already emits definite lengths and shortest-form integers, and preserves `Value::Map`
//! entry order, so sorting the `Value` tree before encoding is sufficient. Parsers reject maps
//! with duplicate keys. Unknown keys are kept as `extras` and are re-emitted (sorted in with the
//! known keys) on write.
//!
//! # Forward compatibility (01 §9)
//!
//! Besides unknown keys, unknown *enum strings* are tolerated so an older build can open a file
//! a newer one wrote: an unknown `slot.kind` becomes an [`OpaqueSlot`] (preserved, never used),
//! an unknown `item.kind` / `field.kind` becomes `ItemKind::Other` / `FieldKind::Other` with the
//! original string in `kind_raw`. Wrong CBOR types, missing required keys and bad lengths
//! remain `Malformed`.

use std::collections::BTreeSet;

use ciborium::Value;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{NONCE_LEN, WRAPPED_KEY_LEN};
use crate::error::VaultError;
use crate::item::{Extras, Field, FieldKind, HistoryEntry, Item, ItemKind, Millis};
use crate::kdf::KdfParams;

/// Lowest format version this build reads. Version 0 never existed and is rejected.
pub const MIN_FORMAT_VERSION: u16 = 1;

/// File magic.
pub const MAGIC: [u8; 4] = *b"RVLT";
/// The format version this build writes and the newest it reads.
pub const FORMAT_VERSION: u16 = 1;
/// `magic(4) || format_version(2) || header_len(4)`.
pub const PREFIX_LEN: usize = 10;
/// The only KDF algorithm the format knows.
pub const KDF_ALG_ARGON2ID: &str = "argon2id";

type Nonce = [u8; NONCE_LEN];

// ---------------------------------------------------------------------------------------------
// AAD layouts
// ---------------------------------------------------------------------------------------------

/// AAD for wrapping/unwrapping a key slot (01 §2):
///
/// ```text
/// magic(4) || format_version_be16(2) || vault_id(16) || slot.id(16) || slot.kind as UTF-8 (no terminator)
/// ```
///
/// `format_version` is the version read from (or about to be written to) the file prefix, as a
/// `u16` big-endian — the spec writes it without a width, so the prefix width is used (the
/// stricter, prefix-matching reading). KDF params are deliberately not bound (they must be
/// rotatable). `kind` is the exact on-disk string; this crate never wraps or unwraps under a
/// [`SlotKind::Other`] kind (such slots are opaque, see [`OpaqueSlot`]).
pub fn slot_aad(format_version: u16, vault_id: Uuid, slot_id: Uuid, kind: &SlotKind) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 2 + 16 + 16 + 8);
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&format_version.to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(slot_id.as_bytes());
    aad.extend_from_slice(kind.as_str().as_bytes());
    aad
}

/// AAD for an item record (01 §4):
///
/// ```text
/// vault_id(16) || item.id(16) || modified_at_be64(8) || format_version_be16(2)
/// ```
///
/// `format_version` is the version from the file prefix.
pub fn item_aad(
    format_version: u16,
    vault_id: Uuid,
    item_id: Uuid,
    modified_at: Millis,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + 8 + 2);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(item_id.as_bytes());
    aad.extend_from_slice(&modified_at.to_be_bytes());
    aad.extend_from_slice(&format_version.to_be_bytes());
    aad
}

/// AAD for the manifest record (01 §4):
///
/// ```text
/// vault_id(16) || item_count_be32(4) || format_version_be16(2)
/// ```
///
/// `format_version` is the version from the file prefix; `item_count` is the number of
/// `ItemRecord`s in the body (tombstones included).
pub fn manifest_aad(format_version: u16, vault_id: Uuid, item_count: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + 2);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&item_count.to_be_bytes());
    aad.extend_from_slice(&format_version.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------------------------

fn malformed(msg: impl Into<String>) -> VaultError {
    VaultError::Malformed(msg.into())
}

/// Upper-bound estimate of the encoded size of `value`, so `encode` can allocate once and never
/// leave stale plaintext fragments behind in reallocated buffers.
fn estimate_len(value: &Value) -> usize {
    const HEAD: usize = 9; // worst-case major-type header
    match value {
        Value::Bytes(b) => HEAD + b.len(),
        Value::Text(t) => HEAD + t.len(),
        Value::Array(a) => HEAD + a.iter().map(estimate_len).sum::<usize>(),
        Value::Map(m) => {
            HEAD + m
                .iter()
                .map(|(k, v)| estimate_len(k) + estimate_len(v))
                .sum::<usize>()
        }
        Value::Tag(_, inner) => HEAD + estimate_len(inner),
        _ => HEAD,
    }
}

/// Encode a `Value` to bytes. Infallible for in-memory output. The output buffer is sized up
/// front from [`estimate_len`] so it is written exactly once.
pub(crate) fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(estimate_len(value));
    ciborium::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

/// Decode exactly one CBOR item from `bytes`; trailing bytes are `Malformed`.
pub(crate) fn decode_exact(bytes: &[u8], what: &str) -> Result<Value, VaultError> {
    let mut reader: &[u8] = bytes;
    let value: Value = ciborium::from_reader(&mut reader)
        .map_err(|e| malformed(format!("{what}: invalid CBOR: {e}")))?;
    if !reader.is_empty() {
        return Err(malformed(format!(
            "{what}: {} trailing bytes after CBOR item",
            reader.len()
        )));
    }
    Ok(value)
}

/// Canonical key order: bytewise lexicographic order of the encoded key (RFC 8949 §4.2.1).
/// Because the CBOR head byte encodes major type and (short) length, text keys shorter than 24
/// bytes still sort before longer ones, but this is *not* the RFC 7049 length-first rule.
fn canonical_sort_key(key: &Value) -> Vec<u8> {
    encode(key)
}

/// Recursively sort every map so that encoding yields canonical CBOR.
pub(crate) fn canonicalize(value: Value) -> Value {
    match value {
        Value::Map(entries) => {
            let mut entries: Vec<(Value, Value)> = entries
                .into_iter()
                .map(|(k, v)| (canonicalize(k), canonicalize(v)))
                .collect();
            entries.sort_by_cached_key(|(k, _)| canonical_sort_key(k));
            Value::Map(entries)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        Value::Tag(tag, inner) => Value::Tag(tag, Box::new(canonicalize(*inner))),
        other => other,
    }
}

/// True if every map in `value` is in canonical key order with no duplicate keys.
pub fn is_canonical(value: &Value) -> bool {
    match value {
        Value::Map(entries) => {
            let keys: Vec<_> = entries.iter().map(|(k, _)| canonical_sort_key(k)).collect();
            keys.windows(2).all(|w| w[0] < w[1])
                && entries
                    .iter()
                    .all(|(k, v)| is_canonical(k) && is_canonical(v))
        }
        Value::Array(items) => items.iter().all(is_canonical),
        Value::Tag(_, inner) => is_canonical(inner),
        _ => true,
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// Build a map from known entries plus extras. Extras whose key collides with a known key are
/// dropped so a map can never contain duplicate keys.
fn build_map(known: Vec<(&str, Value)>, extras: &Extras) -> Value {
    // Known values (which may be plaintext field values) are moved, never cloned.
    let known_keys: Vec<&str> = known.iter().map(|(k, _)| *k).collect();
    let mut entries: Vec<(Value, Value)> = known.into_iter().map(|(k, v)| (text(k), v)).collect();
    for (k, v) in extras {
        let collides = matches!(k, Value::Text(s) if known_keys.contains(&s.as_str()));
        if !collides {
            entries.push((k.clone(), v.clone()));
        }
    }
    Value::Map(entries)
}

/// Pulls known keys out of a decoded map and hands back the rest as extras.
struct MapReader {
    ctx: &'static str,
    entries: Vec<(Value, Value)>,
}

impl MapReader {
    fn new(ctx: &'static str, value: Value) -> Result<Self, VaultError> {
        let Value::Map(entries) = value else {
            return Err(malformed(format!("{ctx}: expected a map")));
        };
        let mut seen = BTreeSet::new();
        for (k, _) in &entries {
            if !seen.insert(encode(k)) {
                return Err(malformed(format!("{ctx}: duplicate map key {k:?}")));
            }
        }
        Ok(Self { ctx, entries })
    }

    fn take(&mut self, key: &str) -> Option<Value> {
        let idx = self
            .entries
            .iter()
            .position(|(k, _)| matches!(k, Value::Text(s) if s == key))?;
        Some(self.entries.remove(idx).1)
    }

    fn required(&mut self, key: &str) -> Result<Value, VaultError> {
        self.take(key)
            .ok_or_else(|| malformed(format!("{}: missing key {key:?}", self.ctx)))
    }

    fn finish(self) -> Extras {
        self.entries
    }
}

fn as_text(v: Value, what: &str) -> Result<String, VaultError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(malformed(format!("{what}: expected text"))),
    }
}

fn as_bool(v: Value, what: &str) -> Result<bool, VaultError> {
    match v {
        Value::Bool(b) => Ok(b),
        _ => Err(malformed(format!("{what}: expected bool"))),
    }
}

fn as_u64(v: Value, what: &str) -> Result<u64, VaultError> {
    match v {
        Value::Integer(i) => {
            u64::try_from(i).map_err(|_| malformed(format!("{what}: out of u64 range")))
        }
        _ => Err(malformed(format!("{what}: expected unsigned integer"))),
    }
}

fn as_u32(v: Value, what: &str) -> Result<u32, VaultError> {
    match v {
        Value::Integer(i) => {
            u32::try_from(i).map_err(|_| malformed(format!("{what}: out of u32 range")))
        }
        _ => Err(malformed(format!("{what}: expected unsigned integer"))),
    }
}

fn as_bytes(v: Value, what: &str) -> Result<Vec<u8>, VaultError> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(malformed(format!("{what}: expected bytes"))),
    }
}

fn as_array(v: Value, what: &str) -> Result<Vec<Value>, VaultError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(malformed(format!("{what}: expected array"))),
    }
}

fn as_fixed<const N: usize>(v: Value, what: &str) -> Result<[u8; N], VaultError> {
    let b = as_bytes(v, what)?;
    <[u8; N]>::try_from(b.as_slice())
        .map_err(|_| malformed(format!("{what}: expected {N} bytes, got {}", b.len())))
}

fn as_uuid(v: Value, what: &str) -> Result<Uuid, VaultError> {
    Ok(Uuid::from_bytes(as_fixed::<16>(v, what)?))
}

fn opt_u64(v: Option<Value>, what: &str) -> Result<Option<u64>, VaultError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(v) => as_u64(v, what).map(Some),
    }
}

fn opt_text(v: Option<Value>, what: &str) -> Result<Option<String>, VaultError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(v) => as_text(v, what).map(Some),
    }
}

// ---------------------------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------------------------

/// `KeySlot.kind`.
///
/// Forward compatibility (01 §9): a kind string this build does not know is reported as
/// [`SlotKind::Other`] by [`Slot::kind`]; the slot itself is kept as an [`OpaqueSlot`] and
/// never used to unlock.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// KEK = Argon2id(password).
    Password,
    /// KEK held in the Keychain behind Touch ID (phase 4).
    Enclave,
    /// Reserved (v2).
    Recovery,
    /// A kind this build does not know (written by a newer version). Holds the exact on-disk
    /// string. Never produced for a known string.
    Other(String),
}

impl SlotKind {
    pub fn as_str(&self) -> &str {
        match self {
            SlotKind::Password => "password",
            SlotKind::Enclave => "enclave",
            SlotKind::Recovery => "recovery",
            SlotKind::Other(s) => s,
        }
    }

    /// Known kinds only; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "password" => Some(SlotKind::Password),
            "enclave" => Some(SlotKind::Enclave),
            "recovery" => Some(SlotKind::Recovery),
            _ => None,
        }
    }

    /// Total inverse of [`SlotKind::as_str`]: unknown strings become [`SlotKind::Other`].
    pub fn from_raw(s: &str) -> Self {
        Self::parse(s).unwrap_or_else(|| SlotKind::Other(s.to_owned()))
    }
}

/// One wrapped copy of `vault_key` (01 §2) of a *known* kind. Contains only ciphertext, so
/// `Debug` is fine. This crate only ever constructs these with a known [`SlotKind`]; a slot
/// whose `kind` string is unknown is parsed as an [`OpaqueSlot`] instead.
#[derive(Debug, Clone, PartialEq)]
pub struct KeySlot {
    pub id: Uuid,
    pub kind: SlotKind,
    pub nonce: Nonce,
    /// `XChaCha20-Poly1305(vault_key)`: 32 bytes ciphertext + 16 bytes tag.
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
    /// Unix seconds.
    pub created_at: u64,
    pub extras: Extras,
}

impl KeySlot {
    fn to_value(&self) -> Value {
        build_map(
            vec![
                ("id", bytes(self.id.as_bytes())),
                ("kind", text(self.kind.as_str())),
                ("nonce", bytes(&self.nonce)),
                ("wrapped_key", bytes(&self.wrapped_key)),
                ("created_at", Value::from(self.created_at)),
            ],
            &self.extras,
        )
    }

    /// `id` and `kind` have already been taken from `m` by [`Slot::from_value`].
    fn from_reader(mut m: MapReader, id: Uuid, kind: SlotKind) -> Result<Self, VaultError> {
        let nonce = as_fixed::<NONCE_LEN>(m.required("nonce")?, "slot.nonce")?;
        let wrapped_key =
            as_fixed::<WRAPPED_KEY_LEN>(m.required("wrapped_key")?, "slot.wrapped_key")?;
        let created_at = as_u64(m.required("created_at")?, "slot.created_at")?;
        Ok(Self {
            id,
            kind,
            nonce,
            wrapped_key,
            created_at,
            extras: m.finish(),
        })
    }
}

/// A slot whose `kind` this build does not know (01 §9 forward compatibility: a newer version
/// added an unlock method). Only `id` (16 bytes) and `kind` (text) are interpreted, so a
/// future kind need not even carry `nonce`/`wrapped_key`; **every other entry of the map is
/// kept verbatim** in `extras` and written back in the slot's original position, so the newer
/// version still finds its slot intact after this build re-saves the file. Never used to
/// unlock; [`UnlockedVault::remove_slot`](crate::UnlockedVault::remove_slot) may drop it by
/// id, and [`UnlockedVault::rotate_vault_key`](crate::UnlockedVault::rotate_vault_key) drops
/// it (its KEK cannot be re-wrapped here, same as an `enclave` slot).
///
/// Interpretation: `id` is required even for unknown kinds (the stricter reading of 01 §2,
/// and the only handle the app has to remove the slot); a missing or mis-sized `id` is
/// `Malformed`. Slot ids must be unique within a header (duplicates are `Malformed`).
///
/// The fields are private so that an `OpaqueSlot` can never carry a *known* kind: one with
/// `kind == "password"` would serialise as a password slot without `nonce`/`wrapped_key`.
/// [`OpaqueSlot::new`] enforces this.
#[derive(Debug, Clone, PartialEq)]
pub struct OpaqueSlot {
    id: Uuid,
    /// The exact on-disk `kind` string (never a known kind).
    kind: String,
    /// Every map entry except `id` and `kind`, verbatim.
    extras: Extras,
}

impl OpaqueSlot {
    /// Build an opaque slot (mainly for tests and fixture generators; the parser builds them
    /// from files).
    ///
    /// # Errors
    ///
    /// `Malformed` if `kind` is a known [`SlotKind`] string (that must be a [`KeySlot`]) or
    /// if `extras` contains an `id` or `kind` key (they would be silently dropped on write).
    pub fn new(id: Uuid, kind: impl Into<String>, extras: Extras) -> Result<Self, VaultError> {
        let kind = kind.into();
        if SlotKind::parse(&kind).is_some() {
            return Err(malformed(format!(
                "opaque slot: {kind:?} is a known slot kind; use KeySlot"
            )));
        }
        if extras
            .iter()
            .any(|(k, _)| matches!(k, Value::Text(s) if s == "id" || s == "kind"))
        {
            return Err(malformed("opaque slot: extras must not contain id or kind"));
        }
        Ok(Self { id, kind, extras })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    /// The exact on-disk `kind` string.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Every map entry except `id` and `kind`, verbatim (canonical key order when parsed).
    pub fn extras(&self) -> &Extras {
        &self.extras
    }

    fn to_value(&self) -> Value {
        debug_assert!(SlotKind::parse(&self.kind).is_none());
        build_map(
            vec![
                ("id", bytes(self.id.as_bytes())),
                ("kind", text(&self.kind)),
            ],
            &self.extras,
        )
    }
}

/// One entry of `header.slots`: a slot this build can use, or an opaque one it only preserves.
#[derive(Debug, Clone, PartialEq)]
pub enum Slot {
    Key(KeySlot),
    Opaque(OpaqueSlot),
}

impl Slot {
    pub fn id(&self) -> Uuid {
        match self {
            Slot::Key(k) => k.id,
            Slot::Opaque(o) => o.id,
        }
    }

    /// The slot's kind; [`SlotKind::Other`] for an opaque slot.
    pub fn kind(&self) -> SlotKind {
        match self {
            Slot::Key(k) => k.kind.clone(),
            Slot::Opaque(o) => SlotKind::Other(o.kind.clone()),
        }
    }

    pub fn as_key(&self) -> Option<&KeySlot> {
        match self {
            Slot::Key(k) => Some(k),
            Slot::Opaque(_) => None,
        }
    }

    pub fn as_key_mut(&mut self) -> Option<&mut KeySlot> {
        match self {
            Slot::Key(k) => Some(k),
            Slot::Opaque(_) => None,
        }
    }

    /// True for a usable slot of the given known kind.
    pub fn is_key_of(&self, kind: SlotKind) -> bool {
        self.as_key().is_some_and(|k| k.kind == kind)
    }

    fn to_value(&self) -> Value {
        match self {
            Slot::Key(k) => k.to_value(),
            Slot::Opaque(o) => o.to_value(),
        }
    }

    /// Unknown `kind` strings are tolerated (opaque slot); everything else that is wrong with
    /// the map (not a map, duplicate keys, missing or mis-typed `id`/`kind`, and for known
    /// kinds a bad `nonce`/`wrapped_key`/`created_at`) is still `Malformed`.
    fn from_value(value: Value) -> Result<Self, VaultError> {
        let mut m = MapReader::new("slot", value)?;
        let id = as_uuid(m.required("id")?, "slot.id")?;
        let kind_str = as_text(m.required("kind")?, "slot.kind")?;
        match SlotKind::parse(&kind_str) {
            Some(kind) => KeySlot::from_reader(m, id, kind).map(Slot::Key),
            None => Ok(Slot::Opaque(OpaqueSlot {
                id,
                kind: kind_str,
                extras: m.finish(),
            })),
        }
    }
}

/// The plaintext header map (01 §2). Contains no secrets.
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    /// The version from the file prefix (not part of the CBOR map). Bound into every AAD.
    pub format_version: u16,
    pub vault_id: Uuid,
    /// Unix seconds.
    pub created_at: u64,
    pub kdf: KdfParams,
    /// Unknown keys inside the `kdf` sub-map.
    pub kdf_extras: Extras,
    /// At least one (opaque slots count). File order is preserved.
    pub slots: Vec<Slot>,
    /// Unknown top-level header keys.
    pub extras: Extras,
}

impl Header {
    /// The header as a (not yet canonicalised) `Value`.
    pub fn to_value(&self) -> Value {
        let kdf = build_map(
            vec![
                ("alg", text(KDF_ALG_ARGON2ID)),
                ("m_cost", Value::from(self.kdf.m_cost_kib)),
                ("t_cost", Value::from(self.kdf.t_cost)),
                ("p_cost", Value::from(self.kdf.p_cost)),
                ("salt", bytes(&self.kdf.salt)),
            ],
            &self.kdf_extras,
        );
        build_map(
            vec![
                ("vault_id", bytes(self.vault_id.as_bytes())),
                ("created_at", Value::from(self.created_at)),
                ("kdf", kdf),
                (
                    "slots",
                    Value::Array(self.slots.iter().map(Slot::to_value).collect()),
                ),
            ],
            &self.extras,
        )
    }

    /// Canonical CBOR bytes of the header map (without the 10-byte file prefix).
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&canonicalize(self.to_value()))
    }

    /// Decode the header map. `format_version` is the value read from the file prefix; it is
    /// stored on the header so the AADs can bind it.
    pub fn from_value(value: Value, format_version: u16) -> Result<Self, VaultError> {
        let mut m = MapReader::new("header", value)?;
        let vault_id = as_uuid(m.required("vault_id")?, "header.vault_id")?;
        let created_at = as_u64(m.required("created_at")?, "header.created_at")?;

        let mut k = MapReader::new("header.kdf", m.required("kdf")?)?;
        let alg = as_text(k.required("alg")?, "kdf.alg")?;
        if alg != KDF_ALG_ARGON2ID {
            return Err(malformed(format!("kdf.alg: unsupported algorithm {alg:?}")));
        }
        let kdf = KdfParams {
            m_cost_kib: as_u32(k.required("m_cost")?, "kdf.m_cost")?,
            t_cost: as_u32(k.required("t_cost")?, "kdf.t_cost")?,
            p_cost: as_u32(k.required("p_cost")?, "kdf.p_cost")?,
            salt: as_fixed::<32>(k.required("salt")?, "kdf.salt")?,
        };
        kdf.validate()?;
        let kdf_extras = k.finish();

        let slots = as_array(m.required("slots")?, "header.slots")?
            .into_iter()
            .map(Slot::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        if slots.is_empty() {
            return Err(malformed("header.slots: at least one slot required"));
        }
        // Ids are the only handle `unlock_with_kek` / `remove_slot` have; a duplicate (e.g. an
        // opaque slot shadowing an enclave slot's id) would make lookups order-dependent.
        let mut ids = BTreeSet::new();
        if let Some(dup) = slots.iter().map(Slot::id).find(|id| !ids.insert(*id)) {
            return Err(malformed(format!("header.slots: duplicate slot id {dup}")));
        }
        Ok(Self {
            format_version,
            vault_id,
            created_at,
            kdf,
            kdf_extras,
            slots,
            extras: m.finish(),
        })
    }

    /// Parse header bytes (the CBOR map only); see [`Header::from_value`].
    pub fn from_bytes(bytes: &[u8], format_version: u16) -> Result<Self, VaultError> {
        Self::from_value(decode_exact(bytes, "header")?, format_version)
    }
}

// ---------------------------------------------------------------------------------------------
// Body records
// ---------------------------------------------------------------------------------------------

const RECORD_ITEM: &str = "item";
const RECORD_MANIFEST: &str = "manifest";

/// An encrypted item (01 §4). Ciphertext only; `Debug` is fine.
#[derive(Debug, Clone, PartialEq)]
pub struct ItemRecord {
    pub id: Uuid,
    pub modified_at: Millis,
    pub nonce: Nonce,
    /// `XChaCha20-Poly1305(CBOR(ItemPlain))` under `item_key`.
    pub ct: Vec<u8>,
    /// Unknown record-level keys. Note these are plaintext and *not* authenticated.
    pub extras: Extras,
}

impl ItemRecord {
    fn to_value(&self) -> Value {
        build_map(
            vec![
                ("t", text(RECORD_ITEM)),
                ("id", bytes(self.id.as_bytes())),
                ("modified_at", Value::from(self.modified_at)),
                ("nonce", bytes(&self.nonce)),
                ("ct", bytes(&self.ct)),
            ],
            &self.extras,
        )
    }

    fn from_reader(mut m: MapReader) -> Result<Self, VaultError> {
        let id = as_uuid(m.required("id")?, "item.id")?;
        let modified_at = as_u64(m.required("modified_at")?, "item.modified_at")?;
        let nonce = as_fixed::<NONCE_LEN>(m.required("nonce")?, "item.nonce")?;
        let ct = as_bytes(m.required("ct")?, "item.ct")?;
        Ok(Self {
            id,
            modified_at,
            nonce,
            ct,
            extras: m.finish(),
        })
    }
}

/// The encrypted manifest (01 §4), always the last record.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestRecord {
    pub nonce: Nonce,
    /// `XChaCha20-Poly1305(CBOR([[id, modified_at], ...]))` under `manifest_key`.
    pub ct: Vec<u8>,
    /// Unknown record-level keys. Plaintext, not authenticated.
    pub extras: Extras,
}

impl ManifestRecord {
    fn to_value(&self) -> Value {
        build_map(
            vec![
                ("t", text(RECORD_MANIFEST)),
                ("nonce", bytes(&self.nonce)),
                ("ct", bytes(&self.ct)),
            ],
            &self.extras,
        )
    }

    fn from_reader(mut m: MapReader) -> Result<Self, VaultError> {
        let nonce = as_fixed::<NONCE_LEN>(m.required("nonce")?, "manifest.nonce")?;
        let ct = as_bytes(m.required("ct")?, "manifest.ct")?;
        Ok(Self {
            nonce,
            ct,
            extras: m.finish(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Record {
    Item(ItemRecord),
    Manifest(ManifestRecord),
}

impl Record {
    fn from_value(value: Value) -> Result<Self, VaultError> {
        let mut m = MapReader::new("record", value)?;
        let t = as_text(m.required("t")?, "record.t")?;
        match t.as_str() {
            RECORD_ITEM => ItemRecord::from_reader(m).map(Record::Item),
            RECORD_MANIFEST => ManifestRecord::from_reader(m).map(Record::Manifest),
            other => Err(malformed(format!(
                "record.t: unknown record type {other:?}"
            ))),
        }
    }
}

/// A fully parsed (still encrypted) vault file: header + item records + manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultFile {
    pub header: Header,
    /// In file order.
    pub items: Vec<ItemRecord>,
    pub manifest: ManifestRecord,
}

impl VaultFile {
    /// Parse the whole file layout (01 §1). Rejects bad magic, newer versions, a `header_len`
    /// past EOF, trailing bytes after the body array, a body without a manifest, and a manifest
    /// that is not the last record.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < MAGIC.len() {
            return Err(VaultError::Truncated);
        }
        if bytes[..MAGIC.len()] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        if bytes.len() < PREFIX_LEN {
            return Err(VaultError::Truncated);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&version) {
            return Err(VaultError::UnsupportedVersion(version));
        }
        let header_len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        let body_start = PREFIX_LEN
            .checked_add(header_len)
            .ok_or(VaultError::Truncated)?;
        if body_start > bytes.len() {
            return Err(VaultError::Truncated);
        }
        let header = Header::from_bytes(&bytes[PREFIX_LEN..body_start], version)?;

        let body = as_array(decode_exact(&bytes[body_start..], "body")?, "body")?;
        let mut records = body
            .into_iter()
            .map(Record::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = match records.pop() {
            Some(Record::Manifest(m)) => m,
            Some(Record::Item(_)) => {
                return Err(malformed("body: last record is not the manifest"));
            }
            None => return Err(malformed("body: empty, manifest missing")),
        };
        let items = records
            .into_iter()
            .map(|r| match r {
                Record::Item(i) => Ok(i),
                Record::Manifest(_) => Err(malformed("body: manifest must be the last record")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            header,
            items,
            manifest,
        })
    }

    /// Serialise to the 01 §1 layout with a canonical header and body. The prefix carries
    /// `header.format_version`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header = self.header.to_bytes();
        let header_len = u32::try_from(header.len()).expect("header exceeds 4 GiB");
        let mut body: Vec<Value> = self.items.iter().map(ItemRecord::to_value).collect();
        body.push(self.manifest.to_value());
        let body = encode(&canonicalize(Value::Array(body)));

        let mut out = Vec::with_capacity(PREFIX_LEN + header.len() + body.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.header.format_version.to_be_bytes());
        out.extend_from_slice(&header_len.to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
        out
    }
}

// ---------------------------------------------------------------------------------------------
// ItemPlain and manifest payloads
// ---------------------------------------------------------------------------------------------

const ATTACHMENTS_KEY: &str = "attachments";

fn field_to_value(f: &Field) -> Value {
    build_map(
        vec![
            ("name", text(&f.name)),
            ("kind", text(f.kind_str())),
            ("value", text(f.value.expose_secret())),
            ("modified_at", Value::from(f.modified_at)),
            ("section", f.section.as_deref().map_or(Value::Null, text)),
        ],
        &f.extras,
    )
}

fn field_from_value(value: Value) -> Result<Field, VaultError> {
    let mut m = MapReader::new("field", value)?;
    let name = as_text(m.required("name")?, "field.name")?;
    // Unknown kind strings become `FieldKind::Other` + `kind_raw` (01 §9); only a non-text
    // `kind` is structural damage.
    let kind_str = as_text(m.required("kind")?, "field.kind")?;
    let kind = FieldKind::parse(&kind_str).unwrap_or(FieldKind::Other);
    let kind_raw = (kind == FieldKind::Other).then_some(kind_str);
    let value = SecretString::new(as_text(m.required("value")?, "field.value")?);
    let modified_at = as_u64(m.required("modified_at")?, "field.modified_at")?;
    let section = opt_text(m.take("section"), "field.section")?;
    Ok(Field {
        name,
        kind,
        kind_raw,
        value,
        modified_at,
        section,
        extras: m.finish(),
    })
}

fn history_to_value(h: &HistoryEntry) -> Value {
    Value::Map(vec![
        (text("value"), text(h.value.expose_secret())),
        (text("replaced_at"), Value::from(h.replaced_at)),
    ])
}

fn history_from_value(value: Value) -> Result<HistoryEntry, VaultError> {
    let mut m = MapReader::new("history", value)?;
    let value = SecretString::new(as_text(m.required("value")?, "history.value")?);
    let replaced_at = as_u64(m.required("replaced_at")?, "history.replaced_at")?;
    // HistoryEntry has no extras slot; unknown keys here are dropped.
    Ok(HistoryEntry { value, replaced_at })
}

/// Canonical CBOR of `ItemPlain` (01 §4), ready to be sealed. The output is zeroized on drop;
/// the intermediate `ciborium::Value` tree is not (it cannot be), which is an accepted
/// limitation of using a generic CBOR model.
///
/// `attachments` is always written (as `[]`) unless the item's extras already carry a
/// non-empty `attachments` entry read from a newer file, which is then preserved verbatim.
pub fn encode_item_plain(item: &Item) -> Zeroizing<Vec<u8>> {
    // NOTE: the `ciborium::Value` tree built here holds plaintext field values as ordinary
    // `String`s and cannot be zeroized; only the encoded output is. Known entries are moved,
    // not cloned, and `encode` allocates once, to keep the number of stray copies minimal.
    let mut known = vec![
        ("kind", text(item.kind_str())),
        ("title", text(&item.title)),
        (
            "deleted_at",
            item.deleted_at.map_or(Value::Null, Value::from),
        ),
        ("device_id", bytes(item.device_id.as_bytes())),
        ("favorite", Value::Bool(item.favorite)),
        (
            "tags",
            Value::Array(item.tags.iter().map(|t| text(t)).collect()),
        ),
        (
            "fields",
            Value::Array(item.fields.iter().map(field_to_value).collect()),
        ),
        (
            "history",
            Value::Array(item.history.iter().map(history_to_value).collect()),
        ),
    ];
    let has_attachments = item
        .extras
        .iter()
        .any(|(k, _)| matches!(k, Value::Text(s) if s == ATTACHMENTS_KEY));
    if !has_attachments {
        known.push((ATTACHMENTS_KEY, Value::Array(Vec::new())));
    }
    Zeroizing::new(encode(&canonicalize(build_map(known, &item.extras))))
}

/// Decode a decrypted `ItemPlain`; `id` and `modified_at` come from the plaintext record.
pub fn decode_item_plain(plain: &[u8], id: Uuid, modified_at: Millis) -> Result<Item, VaultError> {
    // NOTE: same limitation as `encode_item_plain`: the decoded `Value` tree is not zeroized.
    let mut m = MapReader::new("item", decode_exact(plain, "item")?)?;
    // Unknown kind strings become `ItemKind::Other` + `kind_raw` (01 §9); only a non-text
    // `kind` is structural damage.
    let kind_str = as_text(m.required("kind")?, "item.kind")?;
    let kind = ItemKind::parse(&kind_str).unwrap_or(ItemKind::Other);
    let kind_raw = (kind == ItemKind::Other).then_some(kind_str);
    let title = as_text(m.required("title")?, "item.title")?;
    let deleted_at = opt_u64(Some(m.required("deleted_at")?), "item.deleted_at")?;
    let device_id = as_uuid(m.required("device_id")?, "item.device_id")?;
    let favorite = as_bool(m.required("favorite")?, "item.favorite")?;
    let tags = as_array(m.required("tags")?, "item.tags")?
        .into_iter()
        .map(|t| as_text(t, "item.tags[]"))
        .collect::<Result<Vec<_>, _>>()?;
    let fields = as_array(m.required("fields")?, "item.fields")?
        .into_iter()
        .map(field_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    let history = match m.take("history") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => as_array(v, "item.history")?
            .into_iter()
            .map(history_from_value)
            .collect::<Result<Vec<_>, _>>()?,
    };
    // An empty "attachments" array is exactly what a v1 writer emits, so drop it to keep
    // round-trips extras-free; a non-empty one (v1.1) is left in extras and preserved verbatim.
    let mut extras = m.finish();
    extras.retain(|(k, v)| {
        !(matches!(k, Value::Text(s) if s == ATTACHMENTS_KEY)
            && matches!(v, Value::Array(a) if a.is_empty()))
    });
    Ok(Item {
        id,
        kind,
        kind_raw,
        title,
        deleted_at,
        device_id,
        favorite,
        tags,
        fields,
        history,
        modified_at,
        extras,
    })
}

/// Canonical CBOR of the manifest payload: `[[id, modified_at], ...]` in the order given.
/// Callers must pass pairs sorted by id (01 §4).
pub fn encode_manifest(pairs: &[(Uuid, Millis)]) -> Vec<u8> {
    let arr = pairs
        .iter()
        .map(|(id, m)| Value::Array(vec![bytes(id.as_bytes()), Value::from(*m)]))
        .collect();
    encode(&Value::Array(arr))
}

/// Decode a decrypted manifest payload, preserving its order.
pub fn decode_manifest(plain: &[u8]) -> Result<Vec<(Uuid, Millis)>, VaultError> {
    as_array(decode_exact(plain, "manifest")?, "manifest")?
        .into_iter()
        .map(|pair| {
            let mut pair = as_array(pair, "manifest[]")?.into_iter();
            let (Some(id), Some(m), None) = (pair.next(), pair.next(), pair.next()) else {
                return Err(malformed("manifest[]: expected [id, modified_at]"));
            };
            Ok((
                as_uuid(id, "manifest[].id")?,
                as_u64(m, "manifest[].modified_at")?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_sorts_by_encoded_key_bytes() {
        let v = Value::Map(vec![
            (text("created_at"), Value::Null),
            (text("vault_id"), Value::Null),
            (text("slots"), Value::Null),
            (text("kdf"), Value::Null),
            (text("tags"), Value::Null),
            (text("kind"), Value::Null),
        ]);
        let Value::Map(sorted) = canonicalize(v) else {
            panic!()
        };
        let keys: Vec<_> = sorted
            .iter()
            .map(|(k, _)| match k {
                Value::Text(s) => s.as_str(),
                _ => panic!(),
            })
            .collect();
        assert_eq!(
            keys,
            ["kdf", "kind", "tags", "slots", "vault_id", "created_at"]
        );
        assert!(is_canonical(&Value::Map(sorted)));
    }

    #[test]
    fn decode_exact_rejects_trailing_and_duplicates() {
        let mut b = encode(&Value::Integer(1.into()));
        b.push(0);
        assert!(matches!(
            decode_exact(&b, "x"),
            Err(VaultError::Malformed(_))
        ));
        let dup = Value::Map(vec![(text("a"), Value::Null), (text("a"), Value::Null)]);
        assert!(MapReader::new("x", dup).is_err());
    }

    #[test]
    fn manifest_roundtrip() {
        let pairs = vec![(Uuid::from_u128(1), 5u64), (Uuid::from_u128(2), 7)];
        assert_eq!(decode_manifest(&encode_manifest(&pairs)).unwrap(), pairs);
    }

    #[test]
    fn aad_layouts() {
        let vid = Uuid::from_u128(0x11);
        let sid = Uuid::from_u128(0x22);
        let aad = slot_aad(FORMAT_VERSION, vid, sid, &SlotKind::Password);
        assert_eq!(aad.len(), 4 + 2 + 16 + 16 + 8);
        assert_eq!(&aad[..4], b"RVLT");
        assert_eq!(&aad[4..6], &[0, 1]);
        assert_eq!(&aad[6..22], vid.as_bytes());
        assert_eq!(&aad[22..38], sid.as_bytes());
        assert_eq!(&aad[38..], b"password");

        let aad = item_aad(FORMAT_VERSION, vid, sid, 0x0102);
        assert_eq!(aad.len(), 16 + 16 + 8 + 2);
        assert_eq!(&aad[32..40], &[0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(&aad[40..], &[0, 1]);

        let aad = manifest_aad(FORMAT_VERSION, vid, 3);
        assert_eq!(aad.len(), 16 + 4 + 2);
        assert_eq!(&aad[16..20], &[0, 0, 0, 3]);
        assert_eq!(&aad[20..], &[0, 1]);
    }
}
