//! Item model (`02-core-api.md` "Core types", `01-vault-format.md` §4 `ItemPlain`).
//!
//! `Item`, `Field` and `HistoryEntry` hold secrets, so none of them derive `Debug`; the manual
//! impls redact field values and history.

use std::fmt;

use ciborium::Value;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unix milliseconds. Always passed in by the caller; the core never reads a clock.
pub type Millis = u64;

/// Unknown CBOR map keys read from a file, preserved verbatim on re-serialisation (01 §9).
pub type Extras = Vec<(Value, Value)>;

/// `ItemPlain.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    Note,
    Card,
    Identity,
}

impl ItemKind {
    /// All variants, in declaration order.
    pub const ALL: [ItemKind; 4] = [
        ItemKind::Login,
        ItemKind::Note,
        ItemKind::Card,
        ItemKind::Identity,
    ];

    /// The on-disk string.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Login => "login",
            ItemKind::Note => "note",
            ItemKind::Card => "card",
            ItemKind::Identity => "identity",
        }
    }

    /// Inverse of [`ItemKind::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// `Field.kind`.
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
    Number,
}

impl FieldKind {
    /// All variants, in declaration order.
    pub const ALL: [FieldKind; 9] = [
        FieldKind::Text,
        FieldKind::Password,
        FieldKind::Totp,
        FieldKind::Url,
        FieldKind::Notes,
        FieldKind::Email,
        FieldKind::Date,
        FieldKind::MonthYear,
        FieldKind::Number,
    ];

    /// The on-disk string.
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
            FieldKind::Number => "number",
        }
    }

    /// Inverse of [`FieldKind::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One named value inside an item. `value` is the merge unit (03-sync.md).
#[derive(Clone)]
pub struct Field {
    /// Unique within the item, e.g. `"username"`, `"password"`, `"totp"`.
    pub name: String,
    pub kind: FieldKind,
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
            value,
            modified_at: now,
            section: None,
            extras: Vec::new(),
        }
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("name", &self.name)
            .field("kind", &self.kind)
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

/// A decrypted item. `id` and `modified_at` are stored in plaintext on the record; everything
/// else is inside the ciphertext.
#[derive(Clone)]
pub struct Item {
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    /// Tombstone when `Some`.
    pub deleted_at: Option<Millis>,
    /// Device that made the latest change.
    pub device_id: Uuid,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub fields: Vec<Field>,
    pub history: Vec<HistoryEntry>,
    /// Must equal `max(field.modified_at, deleted_at, metadata change)`; the writer maintains it.
    pub modified_at: Millis,
    /// Unknown `ItemPlain` keys preserved from the file (01 §9). A v1.1 `attachments` array
    /// also lands here so that a v1 writer does not drop it.
    pub extras: Extras,
}

impl Item {
    /// A fresh item with a random id, no fields, `modified_at = now`.
    pub fn new(kind: ItemKind, title: impl Into<String>, device_id: Uuid, now: Millis) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            title: title.into(),
            deleted_at: None,
            device_id,
            favorite: false,
            tags: Vec::new(),
            fields: Vec::new(),
            history: Vec::new(),
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
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("kind", &self.kind)
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
        for k in ItemKind::ALL {
            let v = Value::serialized(&k).unwrap();
            assert_eq!(v, Value::Text(k.as_str().to_owned()));
            assert_eq!(ItemKind::parse(k.as_str()), Some(k));
        }
        for k in FieldKind::ALL {
            let v = Value::serialized(&k).unwrap();
            assert_eq!(v, Value::Text(k.as_str().to_owned()));
            assert_eq!(FieldKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(FieldKind::parse("nope"), None);
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut item = Item::new(ItemKind::Login, "t", Uuid::nil(), 1);
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
        let s = format!("{item:?} {:?} {:?}", item.fields[0], item.history[0]);
        assert!(!s.contains("hunter"));
        assert!(!s.contains("secret-"));
        assert!(s.contains("REDACTED"));
        assert!(s.contains("1 extras redacted"));
    }
}
