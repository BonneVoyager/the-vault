//! KDBX 3/4 parsing is delegated to keepass-rs; this module only maps its data model.
//! The dependency zeroizes credentials and protected fields. Its XML/unprotected
//! field allocations are not guaranteed to be wiped (as with the 1PUX JSON parser).

use std::io::Cursor;

use keepass::{Database, DatabaseKey, config::DatabaseVersion, db::Entry};
use secrecy::{ExposeSecret as _, SecretString};
use uuid::Uuid;

use super::ImportError;
use crate::item::{Field, FieldKind, HistoryEntry, Item, ItemKind, Millis};

/// Import entries with fresh IDs and importer-supplied stamps. Group paths become
/// tags; recycle-bin entries are excluded. Attachments, icons and auto-type settings
/// are not imported. `keyfile` is raw key-file content, never a filesystem path.
pub fn import_kdbx(
    bytes: &[u8],
    password: &SecretString,
    keyfile: Option<&[u8]>,
    device_id: Uuid,
    now: Millis,
) -> Result<Vec<Item>, ImportError> {
    if bytes.len() > 100 * 1024 * 1024 || keyfile.is_some_and(|key| key.len() > 1024 * 1024) {
        return Err(ImportError::Malformed(
            "KeePass input exceeds the size limit".into(),
        ));
    }
    match Database::get_version(&mut Cursor::new(bytes)) {
        Ok(DatabaseVersion::KDB3(_) | DatabaseVersion::KDB4(_)) => {}
        _ => {
            return Err(ImportError::Malformed(
                "expected a KDBX 3 or 4 database".into(),
            ));
        }
    }
    let mut key = DatabaseKey::new();
    // An empty password with a key file means key-file-only authentication.
    if keyfile.is_none() || !password.expose_secret().is_empty() {
        key = key.with_password(password.expose_secret());
    }
    if let Some(bytes) = keyfile {
        key = key
            .with_keyfile(&mut Cursor::new(bytes))
            .map_err(|_| ImportError::KdbxCredentials)?;
    }
    let database = Database::parse(bytes, key).map_err(|_| ImportError::KdbxCredentials)?;
    let mut items = Vec::new();
    let mut groups = vec![(database.root().id(), Vec::<String>::new())];
    while let Some((id, path)) = groups.pop() {
        let Some(group) = database.group(id) else {
            continue;
        };
        if Some(group.id().uuid()) == database.meta.recyclebin_uuid {
            continue;
        }
        for entry in group.entries() {
            let mut item = convert(&entry, device_id, now);
            if !path.is_empty() {
                let tag = path.join("/");
                if !item.tags.contains(&tag) {
                    item.tags.push(tag);
                }
            }
            items.push(item);
        }
        for child in group.groups() {
            let mut next = path.clone();
            next.push(child.name.clone());
            groups.push((child.id(), next));
        }
    }
    Ok(items)
}

fn convert(entry: &Entry, device_id: Uuid, now: Millis) -> Item {
    let mut item = Item::new(
        ItemKind::Login,
        entry.get_title().unwrap_or("Untitled"),
        device_id,
        now,
    );
    item.tags = entry.tags.clone();
    let mut fields: Vec<_> = entry
        .fields
        .iter()
        .filter(|(name, _)| name.as_str() != "Title")
        .collect();
    fields.sort_by_key(|(name, _)| {
        (
            match name.as_str() {
                "UserName" => 0,
                "Password" => 1,
                "URL" => 2,
                "Notes" => 3,
                _ => 4,
            },
            name.as_str(),
        )
    });
    for (name, value) in fields {
        let (name, kind) = match name.as_str() {
            "UserName" => ("username", FieldKind::Text),
            "Password" => ("password", FieldKind::Password),
            "URL" => ("website", FieldKind::Url),
            "Notes" => ("notes", FieldKind::Notes),
            "otp" => ("totp", FieldKind::Totp),
            name => (
                name,
                if value.is_protected() {
                    FieldKind::Password
                } else {
                    FieldKind::Text
                },
            ),
        };
        let mut unique = name.to_owned();
        let mut suffix = 2;
        while item.fields.iter().any(|field| field.name == unique) {
            unique = format!("{name} ({suffix})");
            suffix += 1;
        }
        item.fields.push(Field::new(
            unique,
            kind,
            SecretString::new(value.get().clone()),
            now,
        ));
    }
    if let Some(history) = &entry.history {
        item.history = history
            .get_entries()
            .iter()
            .filter_map(|version| {
                Some(HistoryEntry {
                    value: SecretString::new(version.get_password()?.to_owned()),
                    replaced_at: version
                        .times
                        .last_modification
                        .and_then(|time| u64::try_from(time.and_utc().timestamp_millis()).ok())
                        .unwrap_or(now),
                })
            })
            .collect();
        item.history
            .sort_by_key(|entry| std::cmp::Reverse(entry.replaced_at));
        item.history.truncate(10);
    }
    item
}
