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
    /// A kind this build does not know; the on-disk string is in [`Field::kind_raw`]. Its
    /// value must be masked in any UI (`is_sensitive() == true`).
    Other,
}

impl FieldKind {
    /// Every *known* variant, in declaration order. [`FieldKind::Other`] is not listed.
    pub const ALL: [FieldKind; 8] = [
        FieldKind::Text,
        FieldKind::Password,
        FieldKind::Totp,
        FieldKind::Url,
        FieldKind::Notes,
        FieldKind::Email,
        FieldKind::Date,
        FieldKind::MonthYear,
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
    pub fn is_sensitive(self) -> bool {
        matches!(
            self,
            FieldKind::Password | FieldKind::Totp | FieldKind::Other
        )
    }
}

/// One named value inside an item. `value` is the merge unit (03-sync.md).
#[derive(Clone)]
pub struct Field {
    /// Unique within the item, e.g. `"username"`, `"password"`, `"totp"`.
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
    pub fn new(name: impl Into<String>, kind: FieldKind, value: SecretString, now: Millis) -> Self {
        Self {
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
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
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

/// A previous password value (01 §4). Capped at 10 per item by `set_field` (later package).
#[derive(Clone)]
pub struct HistoryEntry {
    pub value: SecretString,
    pub replaced_at: Millis,
}

impl fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryEntry")
            .field("value", &"[REDACTED]")
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
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
/// pruned). Holds no secret. Capped per item at [`crate::vault::ATTACHMENT_TOMBSTONE_CAP`]
/// and purged with the item tombstones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttachmentTombstone {
    /// The removed reference's id.
    pub id: Uuid,
    /// The item stamp of the removal (unix millis). A reference whose `added_at` is at or
    /// before this is considered removed.
    pub removed_at: Millis,
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
    pub fields: Vec<Field>,
    pub history: Vec<HistoryEntry>,
    /// Attachment references (01 §4, v1.1). Empty for every v1 file. Add and remove through
    /// [`crate::UnlockedVault::add_attachment_ref`] / `remove_attachment_ref` so the item is
    /// restamped; the blobs themselves are managed by `vault-sync`.
    pub attachments: Vec<AttachmentRef>,
    /// Removal markers for attachment references (v1.1), newest first, capped at
    /// [`crate::vault::ATTACHMENT_TOMBSTONE_CAP`]. Written only when non-empty.
    pub removed_attachments: Vec<AttachmentTombstone>,
    /// `replaced_at` stamps of history entries the user deleted (01 §4 `removed_history`),
    /// newest first, deduplicated, capped at [`crate::vault::HISTORY_CAP`]. Never holds the
    /// value. Written only when non-empty. Edit through
    /// [`crate::UnlockedVault::remove_history_entry`] / `clear_history` so the item is
    /// restamped; a merge drops every history entry whose stamp is in this list.
    pub removed_history: Vec<Millis>,
    /// Must equal `max(field.modified_at, deleted_at, metadata change)`; the writer maintains it.
    pub modified_at: Millis,
    /// Unknown `ItemPlain` keys preserved from the file (01 §9).
    pub extras: Extras,
}

impl Item {
    /// A fresh item with a random id, no fields, `modified_at = now`.
    pub fn new(title: impl Into<String>, device_id: Uuid, now: Millis) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            deleted_at: None,
            device_id,
            favorite: false,
            tags: Vec::new(),
            fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            removed_attachments: Vec::new(),
            removed_history: Vec::new(),
            modified_at: now,
            extras: Vec::new(),
        }
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// First field with this name, if any.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
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
        let s = format!(
            "{item:?} {:?} {:?} {:?}",
            item.fields[0], item.history[0], item.attachments[0]
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
