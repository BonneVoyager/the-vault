//! Item model (`02-core-api.md` "Core types", `01-vault-format.md` §4 `ItemPlain`).
//!
//! `Item`, `Field` and `HistoryEntry` hold secrets, so none of them derive `Debug`; the manual
//! impls redact field values and history.

use std::fmt;

use ciborium::Value;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Unix milliseconds. Always passed in by the caller; the core never reads a clock.
pub type Millis = u64;

/// Unknown CBOR map keys read from a file, preserved verbatim on re-serialisation (01 §9).
pub type Extras = Vec<(Value, Value)>;

/// `Field.kind`.
///
/// Forward compatibility (01 §9): a kind string this build does not know parses as
/// [`FieldKind::Other`], with the original string kept in [`Field::kind_raw`] and written back
/// unchanged. The former `"number"` kind (removed 2026-10-30) is handled the same way: it
/// reads as `Other` with `kind_raw = Some("number")` and is preserved on save. **Display rule:** the value of an `Other` field must be treated as sensitive
/// (masked by default, like a password) because this build cannot tell whether a newer kind
/// is secret; see [`FieldKind::is_sensitive`]. Everything else (merge, search, timestamps)
/// treats it as `text`. `Other` is never produced for a known string and is not part of
/// [`FieldKind::ALL`].
///
/// [`FieldKind::Section`] (on-disk `"section"`, added 2026-10-31 as a new enum string, no
/// version bump) is a visual heading, not a value: the field's `name` is the heading text and
/// its `value` is empty and ignored. The core does not enforce the empty value (it stores
/// whatever it is given); the app writes `""`. A section is never sensitive, is skipped by
/// the CSV export, is ignored by search, and `set_field` on one writes nothing to history.
/// It merges like any other field, by name and stamp. A build older than the variant reads
/// it as `Other` with `kind_raw = "section"` and preserves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Password,
    Totp,
    Url,
    Notes,
    Email,
    Date,
    MonthYear,
    /// A visual heading; `name` is the heading, `value` is empty and ignored. See the type
    /// docs.
    Section,
    /// A kind this build does not know; the on-disk string is in [`Field::kind_raw`]. Its
    /// value must be masked in any UI (`is_sensitive() == true`).
    Other,
}

impl FieldKind {
    /// Every *known* variant, in declaration order. [`FieldKind::Other`] is not listed.
    pub const ALL: [FieldKind; 9] = [
        FieldKind::Text,
        FieldKind::Password,
        FieldKind::Totp,
        FieldKind::Url,
        FieldKind::Notes,
        FieldKind::Email,
        FieldKind::Date,
        FieldKind::MonthYear,
        FieldKind::Section,
    ];

    /// The on-disk string of a known kind. For [`FieldKind::Other`] this is the placeholder
    /// `"other"`; use [`Field::kind_str`] to get the real on-disk string.
    pub fn as_str(self) -> &'static str {
        match self {
            FieldKind::Text => "text",
            FieldKind::Password => "password",
            FieldKind::Totp => "totp",
            FieldKind::Url => "url",
            FieldKind::Notes => "notes",
            FieldKind::Email => "email",
            FieldKind::Date => "date",
            FieldKind::MonthYear => "month_year",
            FieldKind::Section => "section",
            FieldKind::Other => "other",
        }
    }

    /// Inverse of [`FieldKind::as_str`] for *known* kinds; `None` for anything else (including
    /// `"other"`). Use this to validate user input; the parser maps `None` to
    /// [`FieldKind::Other`] and keeps the string in [`Field::kind_raw`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// True for [`FieldKind::Other`].
    pub fn is_other(self) -> bool {
        self == FieldKind::Other
    }

    /// Whether a UI must mask this field's value by default: `password`, `totp`, and every
    /// unknown kind (a newer version may have added a secret kind; masking is the safe
    /// default). Card numbers are an item-level rule, not a field kind, and are not covered.
    /// A [`FieldKind::Section`] heading is never sensitive.
    pub fn is_sensitive(self) -> bool {
        matches!(
            self,
            FieldKind::Password | FieldKind::Totp | FieldKind::Other
        )
    }
}

/// One named value inside an item. The field is the merge unit (03-sync.md §5), identified
/// by [`Field::id`], never by name.
///
/// Since FI-1 (2026-10-31, format version 2) a field's identity is its random `id`: names
/// are labels that may repeat within an item and may be empty. A rename is an edit of the
/// same field, not a delete plus an add. Lookups by name ([`Item::field`],
/// [`crate::UnlockedVault::set_field_named`]) are conveniences that pick the first
/// non-section match ASCII case-insensitively and never match an empty name.
#[derive(Clone)]
pub struct Field {
    /// Stable identity, random v4 from [`Field::new`]. Written to the file always; a v1 file
    /// without ids gets deterministic ones on read ([`Field::derived_id`]).
    pub id: Uuid,
    /// Display label, e.g. `"username"`, `"password"`, `"totp"`. Not unique, may be empty.
    pub name: String,
    pub kind: FieldKind,
    /// The exact on-disk `kind` string when `kind == FieldKind::Other` (01 §9), else `None`.
    /// Written back verbatim by `serialize`; ignored for known kinds.
    pub kind_raw: Option<String>,
    /// For `Totp`, the full `otpauth://` URI.
    pub value: SecretString,
    pub modified_at: Millis,
    /// Optional grouping label.
    pub section: Option<String>,
    /// Unknown keys preserved from the file (01 §9).
    pub extras: Extras,
}

impl Field {
    /// A field with a fresh random id.
    pub fn new(name: impl Into<String>, kind: FieldKind, value: SecretString, now: Millis) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            kind,
            kind_raw: None,
            value,
            modified_at: now,
            section: None,
            extras: Vec::new(),
        }
    }

    /// The on-disk kind string the writer emits: the preserved `kind_raw` for an unknown kind
    /// (falling back to the `"other"` placeholder if a caller built an `Other` without one),
    /// else the known kind's string. `kind_raw` is deliberately ignored for known kinds so that
    /// changing a field's kind without clearing `kind_raw` cannot resurrect the old string.
    pub fn kind_str(&self) -> &str {
        if self.kind == FieldKind::Other {
            self.kind_raw.as_deref().unwrap_or("other")
        } else {
            self.kind.as_str()
        }
    }

    /// The id a field of a **format version 1** file gets when the file carries none (01 §9
    /// "version 2 and migration"). Deterministic so that two devices reading the same v1 file
    /// agree without talking: UUIDv5 with the owning item's id as the namespace over the
    /// bytes `"field:" || name || ":" || ordinal`, where `ordinal` is the number of earlier
    /// fields in that item with the same name (so the first `username` is ordinal 0, a
    /// second one 1, ...), written as unpadded decimal ASCII. The name goes in as its UTF-8
    /// bytes; an empty name yields `"field::0"`. The reader applies this only to fields
    /// without an `id` key; the writer always emits ids, so a file saved by this build never
    /// needs the derivation again.
    pub fn derived_id(item_id: Uuid, name: &str, ordinal: usize) -> Uuid {
        let mut input = Vec::with_capacity(6 + name.len() + 1 + 20);
        input.extend_from_slice(b"field:");
        input.extend_from_slice(name.as_bytes());
        input.push(b':');
        input.extend_from_slice(ordinal.to_string().as_bytes());
        Uuid::new_v5(&item_id, &input)
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("kind_raw", &self.kind_raw)
            .field("value", &"[REDACTED]")
            .field("modified_at", &self.modified_at)
            .field("section", &self.section)
            .field(
                "extras",
                &format_args!("[{} extras redacted]", self.extras.len()),
            )
            .finish()
    }
}

/// A previous password value (01 §4). Capped at 10 per item by `set_field`.
#[derive(Clone)]
pub struct HistoryEntry {
    pub value: SecretString,
    pub replaced_at: Millis,
    /// The [`Field::id`] whose value this was (format version 2, optional key `field_id`).
    /// `None` for entries written before field ids existed and for entries a caller pushed
    /// without one; `set_field` on a `password` field records it. Not part of the history
    /// union key (`(value, replaced_at)`), so a v1 entry and its id-carrying twin dedupe to
    /// the one with the id.
    pub field_id: Option<Uuid>,
}

impl fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryEntry")
            .field("value", &"[REDACTED]")
            .field("replaced_at", &self.replaced_at)
            .field("field_id", &self.field_id)
            .finish()
    }
}

/// Removal marker for a field (01 §4 `removed_fields`, format version 2). Written by
/// [`crate::UnlockedVault::remove_field`] and by [`crate::UnlockedVault::update`] for every
/// field id that disappeared, so that a merge with a peer that still carries the field
/// drops it instead of resurrecting it (this closes the "field deletion resurrection" limit
/// of 03 §5). A field edited *after* the removal (strictly greater `modified_at`) survives
/// the merge and the marker is dropped. Holds no secret. Kept newest first and purged with
/// the item tombstones. The cap [`crate::vault::FIELD_TOMBSTONE_CAP`] is applied only by a
/// merge, and only over markers whose field is absent on both sides; a local removal never
/// truncates the list, so it may sit over the cap until a merge has seen both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldTombstone {
    /// The removed field's id.
    pub id: Uuid,
    /// The item stamp of the removal (unix millis). A field whose `modified_at` is at or
    /// before this is considered removed.
    pub removed_at: Millis,
}

/// A reference to one encrypted attachment blob (01 §4 "Attachments (v1.1)"). Lives inside
/// the item's ciphertext, so the name, size and key are encrypted and the reference is
/// authenticated together with the item. The blob itself is immutable and stored next to the
/// vault as `<name>.vault.attachments/<id hex>.bin` (see [`crate::attachment`]).
///
/// Build one with [`crate::attachment::new_ref`]; `key` and `chunk_nonces` are then random
/// and consistent with `size`. No `Debug` derive: the manual impl redacts `key`.
#[derive(Clone)]
pub struct AttachmentRef {
    /// Random v4 id; also the blob file name (`attachment::blob_file_name`).
    pub id: Uuid,
    /// Original file name, for display only (not used to locate the blob).
    pub name: String,
    /// Plaintext length in bytes, at most [`crate::attachment::MAX_ATTACHMENT_SIZE`].
    pub size: u64,
    /// Per-attachment random 32-byte XChaCha20-Poly1305 key, wiped on drop.
    pub key: Zeroizing<[u8; 32]>,
    /// One random 24-byte nonce per chunk; `len()` is the chunk count
    /// (`max(1, ceil(size / CHUNK_SIZE))`).
    pub chunk_nonces: Vec<[u8; 24]>,
    /// When the reference was added (unix millis). Merge order key.
    pub added_at: Millis,
    /// Unknown keys preserved from the file (01 §9).
    pub extras: Extras,
}

impl AttachmentRef {
    /// Number of chunks in the blob (`chunk_nonces.len()`).
    pub fn chunk_count(&self) -> usize {
        self.chunk_nonces.len()
    }
}

impl fmt::Debug for AttachmentRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentRef")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("size", &self.size)
            .field("key", &"[REDACTED]")
            .field(
                "chunk_nonces",
                &format_args!("[{} nonces]", self.chunk_nonces.len()),
            )
            .field("added_at", &self.added_at)
            .field(
                "extras",
                &format_args!("[{} extras redacted]", self.extras.len()),
            )
            .finish()
    }
}

/// Removal marker for an attachment reference (01 §4, v1.1 `removed_attachments`). Written
/// by [`crate::UnlockedVault::remove_attachment_ref`] so that a merge with a peer that still
/// carries the reference drops it instead of resurrecting it (the blob may already be
/// pruned). Holds no secret. Purged with the item tombstones; the per-item cap
/// [`crate::vault::ATTACHMENT_TOMBSTONE_CAP`] is applied only by a merge, to markers whose
/// reference neither side still holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttachmentTombstone {
    /// The removed reference's id.
    pub id: Uuid,
    /// The item stamp of the removal (unix millis). A reference whose `added_at` is at or
    /// before this is considered removed.
    pub removed_at: Millis,
}

/// An optional per-item icon choice (01 §4 `ItemPlain.icon`, v1.2, no version bump). Stored
/// by the core and interpreted by the app: `kind` names how to read `value` (the app uses
/// kinds such as `symbol`, `logo`, `image`), `color` is an optional app-defined colour, and
/// the core validates nothing beyond CBOR types. Nothing here is secret, so `Debug` is
/// derived. No `Eq`: `extras` holds `ciborium::Value`, which is only `PartialEq`.
///
/// Merge treats the icon as item metadata like `favorite` and `tags`: it travels with the
/// metadata winner and a differing icon makes two items unequal. There is no setter on
/// `UnlockedVault`; change it through [`crate::UnlockedVault::update`], which restamps the
/// item unconditionally.
#[derive(Clone, PartialEq, Debug)]
pub struct ItemIcon {
    /// How the app should interpret `value` (e.g. `symbol`, `logo`, `image`). Opaque to core.
    pub kind: String,
    /// The icon reference in the form `kind` implies (symbol name, domain, image id, ...).
    pub value: String,
    /// Optional app-defined colour. Omitted from the file when `None`.
    pub color: Option<String>,
    /// Unknown keys preserved from the icon map (01 §9), so a newer app's additions survive
    /// a read-write cycle by this build.
    pub extras: Extras,
}

impl ItemIcon {
    /// An icon with no colour and no extras.
    pub fn new(kind: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            value: value.into(),
            color: None,
            extras: Vec::new(),
        }
    }
}

/// A decrypted item. `id` and `modified_at` are stored in plaintext on the record; everything
/// else is inside the ciphertext.
///
/// There is no item category: `ItemPlain.kind` was removed on 2026-10-30 (templates add a
/// tag such as `login` / `note` / `card` / `identity` instead). A `kind` key read from an
/// older file is an ordinary unknown key: it lands in [`Item::extras`] and is re-emitted
/// verbatim, so old files round-trip byte-identically. The writer never emits one itself.
#[derive(Clone)]
pub struct Item {
    pub id: Uuid,
    pub title: String,
    /// Tombstone when `Some`.
    pub deleted_at: Option<Millis>,
    /// Device that made the latest change.
    pub device_id: Uuid,
    pub favorite: bool,
    pub tags: Vec<String>,
    /// Optional icon choice (v1.2). `None` for every file written before it existed; the
    /// writer emits the key only when `Some`. Interpreted by the app, see [`ItemIcon`].
    pub icon: Option<ItemIcon>,
    /// When the item was created (unix millis; v1.3, optional, no version bump).
    /// [`Item::new`] sets `Some(now)`; every file written before the key existed reads as
    /// `None`, and the writer emits the key only when `Some`. Immutable metadata: a merge
    /// keeps the minimum of the two sides (or whichever is `Some`), and a differing
    /// `created_at` alone is not a change (it never bumps `modified_at`). Importers set it
    /// from the source's creation time when it has one, else `now`.
    pub created_at: Option<Millis>,
    /// Per-attribute stamps (01 §4, 2026-10-31, optional keys, no bump): unix millis of the
    /// last change to `title`, `favorite`, `tags` (as one set) and `icon`, so that concurrent
    /// edits of *different* attributes on two devices both survive a merge (03 §5). Set by
    /// [`crate::UnlockedVault::update`] when the attribute changes (monotone, like field
    /// stamps) and filled by `insert` with the item stamp; `None` for items written before
    /// the keys existed, which the merge reads as the item's `modified_at`; the first
    /// mutation of such an item pins the unset stamps at the item stamp they implicitly had.
    /// `modified_at` is at least every one of them.
    pub title_modified_at: Option<Millis>,
    pub favorite_modified_at: Option<Millis>,
    pub tags_modified_at: Option<Millis>,
    pub icon_modified_at: Option<Millis>,
    pub fields: Vec<Field>,
    pub history: Vec<HistoryEntry>,
    /// Attachment references (01 §4, v1.1), kept in `(added_at, id)` ascending order, the
    /// merge's canonical order (03 §5), on every write path and on read. Empty for every v1
    /// file. Add and remove through [`crate::UnlockedVault::add_attachment_ref`] /
    /// `remove_attachment_ref` so the item is restamped; the blobs themselves are managed by
    /// `vault-sync`.
    pub attachments: Vec<AttachmentRef>,
    /// Removal markers for attachment references (v1.1), newest first. Written only when
    /// non-empty. Capped at [`crate::vault::ATTACHMENT_TOMBSTONE_CAP`] only by a merge (a
    /// local removal never drops a marker), so the list may be longer in between.
    pub removed_attachments: Vec<AttachmentTombstone>,
    /// `replaced_at` stamps of history entries the user deleted (01 §4 `removed_history`),
    /// newest first, deduplicated, capped at [`crate::vault::HISTORY_CAP`]. Never holds the
    /// value. Written only when non-empty. Edit through
    /// [`crate::UnlockedVault::remove_history_entry`] / `clear_history` so the item is
    /// restamped; a merge drops every history entry whose stamp is in this list.
    pub removed_history: Vec<Millis>,
    /// Removal markers for fields (01 §4 `removed_fields`, format version 2), newest first,
    /// one per id. Written only when
    /// non-empty. Maintained by [`crate::UnlockedVault::update`] /
    /// [`crate::UnlockedVault::remove_field`]; a merge drops every field whose id has a
    /// marker with `removed_at >= field.modified_at`.
    pub removed_fields: Vec<FieldTombstone>,
    /// Must equal `max(field.modified_at, deleted_at, metadata change)`; the writer maintains it.
    pub modified_at: Millis,
    /// Unknown `ItemPlain` keys preserved from the file (01 §9).
    pub extras: Extras,
}

impl Item {
    /// A fresh item with a random id, no fields, `modified_at = now`, `created_at = Some(now)`.
    pub fn new(title: impl Into<String>, device_id: Uuid, now: Millis) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            deleted_at: None,
            device_id,
            favorite: false,
            tags: Vec::new(),
            icon: None,
            created_at: Some(now),
            title_modified_at: None,
            favorite_modified_at: None,
            tags_modified_at: None,
            icon_modified_at: None,
            fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            removed_attachments: Vec::new(),
            removed_history: Vec::new(),
            removed_fields: Vec::new(),
            modified_at: now,
            extras: Vec::new(),
        }
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// The effective stamp of each attribute for the merge (03 §5): the stored stamp, or
    /// the item's `modified_at` when the item carries none.
    pub fn title_stamp(&self) -> Millis {
        self.title_modified_at.unwrap_or(self.modified_at)
    }
    pub fn favorite_stamp(&self) -> Millis {
        self.favorite_modified_at.unwrap_or(self.modified_at)
    }
    pub fn tags_stamp(&self) -> Millis {
        self.tags_modified_at.unwrap_or(self.modified_at)
    }
    pub fn icon_stamp(&self) -> Millis {
        self.icon_modified_at.unwrap_or(self.modified_at)
    }

    /// The first non-section field whose name equals `name` ASCII case-insensitively, if
    /// any. A convenience for templates and importers that address fields by label (02
    /// "search", 2026-10-31 rule); the field's identity is [`Field::id`], see
    /// [`Item::field_by_id`]. Section headings ([`FieldKind::Section`]) never match, and an
    /// empty `name` never matches anything (a field may have an empty name since FI-1, but
    /// nothing looks one up that way).
    pub fn field(&self, name: &str) -> Option<&Field> {
        if name.is_empty() {
            return None;
        }
        self.fields
            .iter()
            .find(|f| f.kind != FieldKind::Section && f.name.eq_ignore_ascii_case(name))
    }

    /// The field with this id, if any.
    pub fn field_by_id(&self, id: Uuid) -> Option<&Field> {
        self.fields.iter().find(|f| f.id == id)
    }

    /// The attachment reference with this id, if any.
    pub fn attachment(&self, id: Uuid) -> Option<&AttachmentRef> {
        self.attachments.iter().find(|a| a.id == id)
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("deleted_at", &self.deleted_at)
            .field("device_id", &self.device_id)
            .field("favorite", &self.favorite)
            .field("tags", &self.tags)
            .field("icon", &self.icon)
            .field("created_at", &self.created_at)
            .field("title_modified_at", &self.title_modified_at)
            .field("favorite_modified_at", &self.favorite_modified_at)
            .field("tags_modified_at", &self.tags_modified_at)
            .field("icon_modified_at", &self.icon_modified_at)
            .field(
                "fields",
                &format_args!("[{} fields redacted]", self.fields.len()),
            )
            .field(
                "history",
                &format_args!("[{} entries redacted]", self.history.len()),
            )
            .field("attachments", &self.attachments)
            .field("removed_attachments", &self.removed_attachments)
            .field("removed_history", &self.removed_history)
            .field("removed_fields", &self.removed_fields)
            .field("modified_at", &self.modified_at)
            .field(
                "extras",
                &format_args!("[{} extras redacted]", self.extras.len()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn kind_strings_match_serde_names() {
        for k in FieldKind::ALL {
            let v = Value::serialized(&k).unwrap();
            assert_eq!(v, Value::Text(k.as_str().to_owned()));
            assert_eq!(FieldKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(FieldKind::parse("nope"), None);
        assert_eq!(
            FieldKind::parse("other"),
            None,
            "placeholder is not a known kind"
        );
        assert_eq!(
            FieldKind::parse("number"),
            None,
            "removed 2026-10-30; reads as Other"
        );
        assert!(!FieldKind::ALL.iter().any(|k| k.as_str() == "number"));
        assert!(FieldKind::Other.is_sensitive() && FieldKind::Password.is_sensitive());
        assert!(!FieldKind::Text.is_sensitive());
        assert_eq!(FieldKind::parse("section"), Some(FieldKind::Section));
        assert_eq!(FieldKind::Section.as_str(), "section");
        assert!(
            !FieldKind::Section.is_sensitive(),
            "a heading is never masked"
        );
    }

    #[test]
    fn derived_field_id_is_uuid_v5_over_the_documented_bytes() {
        let item = Uuid::from_u128(0x1234);
        let id = Field::derived_id(item, "username", 0);
        assert_eq!(id, Uuid::new_v5(&item, b"field:username:0"));
        assert_eq!(id.get_version_num(), 5);
        assert_eq!(
            Field::derived_id(item, "", 7),
            Uuid::new_v5(&item, b"field::7"),
            "empty name, unpadded decimal ordinal"
        );
        assert_ne!(
            Field::derived_id(item, "username", 1),
            id,
            "ordinal matters"
        );
        assert_ne!(
            Field::derived_id(Uuid::from_u128(0x5678), "username", 0),
            id,
            "item id is the namespace"
        );
        assert_ne!(
            Field::derived_id(item, "Username", 0),
            id,
            "name is byte-exact"
        );
    }

    #[test]
    fn field_lookup_by_name_skips_sections_and_empty_names() {
        let mut item = Item::new("t", Uuid::nil(), 1);
        let s = SecretString::new("v".into());
        item.fields
            .push(Field::new("Password", FieldKind::Section, s.clone(), 1));
        item.fields
            .push(Field::new("", FieldKind::Text, s.clone(), 1));
        item.fields
            .push(Field::new("password", FieldKind::Password, s.clone(), 1));
        item.fields
            .push(Field::new("PASSWORD", FieldKind::Text, s, 1));
        assert_eq!(item.field("Password").unwrap().id, item.fields[2].id);
        assert!(item.field("").is_none(), "empty name never matches");
        assert_eq!(item.field_by_id(item.fields[1].id).unwrap().name, "");
        assert!(item.field_by_id(Uuid::nil()).is_none());
        assert!(
            Field::new("x", FieldKind::Text, SecretString::new("".into()), 1).id
                != Field::new("x", FieldKind::Text, SecretString::new("".into()), 1).id
        );
    }

    #[test]
    fn new_item_is_stamped_created_at_now() {
        let item = Item::new("t", Uuid::nil(), 1_234);
        assert_eq!(item.created_at, Some(1_234));
        assert_eq!(item.modified_at, 1_234);
    }

    #[test]
    fn kind_str_prefers_raw_only_for_other() {
        let mut f = Field::new("f", FieldKind::Other, SecretString::new("v".into()), 1);
        assert_eq!(f.kind_str(), "other", "fallback placeholder");
        f.kind_raw = Some("future-field-kind".into());
        assert_eq!(f.kind_str(), "future-field-kind");
        f.kind = FieldKind::Text;
        assert_eq!(f.kind_str(), "text", "raw ignored for known kinds");
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut item = Item::new("t", Uuid::nil(), 1);
        item.fields.push(Field::new(
            "password",
            FieldKind::Password,
            SecretString::new("hunter2".to_owned()),
            1,
        ));
        item.history.push(HistoryEntry {
            value: SecretString::new("hunter1".to_owned()),
            replaced_at: 0,
            field_id: Some(item.fields[0].id),
        });
        item.extras.push((
            Value::Text("attachments".into()),
            Value::Text("secret-att".into()),
        ));
        item.fields[0]
            .extras
            .push((Value::Text("x".into()), Value::Text("secret-ext".into())));
        item.attachments.push(AttachmentRef {
            id: Uuid::nil(),
            name: "doc.pdf".into(),
            size: 3,
            key: Zeroizing::new([0xA7; 32]),
            chunk_nonces: vec![[0xB8; 24]],
            added_at: 2,
            extras: vec![(
                Value::Text("y".into()),
                Value::Text("secret-att-ext".into()),
            )],
        });
        item.icon = Some(ItemIcon {
            kind: "symbol".into(),
            value: "key.fill".into(),
            color: Some("#ff0000".into()),
            extras: vec![(Value::Text("z".into()), Value::Integer(1.into()))],
        });
        let s = format!(
            "{item:?} {:?} {:?} {:?}",
            item.fields[0], item.history[0], item.attachments[0]
        );
        assert!(
            s.contains("key.fill"),
            "icon is not secret: printed in full"
        );
        assert!(!s.contains("hunter"));
        assert!(!s.contains("secret-"));
        assert!(!s.contains("167"), "key byte 0xA7 = 167 must not appear");
        assert!(
            !s.contains("184"),
            "nonce byte 0xB8 = 184 is not printed either"
        );
        assert!(s.contains("doc.pdf"));
        assert!(s.contains("REDACTED"));
        assert!(s.contains("1 extras redacted"));
    }
}
