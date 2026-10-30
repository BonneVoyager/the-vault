//! Plaintext CSV export (`02-core-api.md` "import / export").

use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::item::{FieldKind, Item};
use crate::vault::UnlockedVault;

/// Unencrypted export bytes. A distinct type so they cannot be confused with vault file bytes.
///
/// The bytes are zeroized on drop. Known gap: the `csv::Writer` used to build them keeps an
/// internal buffer that is not zeroized.
pub struct PlaintextExport(pub Vec<u8>);

impl Drop for PlaintextExport {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn value<'a>(item: &'a Item, name: &str, kind: FieldKind) -> &'a str {
    item.fields
        .iter()
        .find(|f| f.name == name)
        .or_else(|| item.fields.iter().find(|f| f.kind == kind))
        .map_or("", |f| f.value.expose_secret().as_str())
}

/// Columns: `title,username,password,url,notes,totp`. Every live item is one row; a column is
/// empty when the item has no matching field. (Item categories were removed on 2026-10-30, so
/// there is no longer a "non-login" gate on the credential columns.)
pub fn export_csv(vault: &UnlockedVault) -> PlaintextExport {
    let mut w = csv::Writer::from_writer(Vec::new());
    // Writing to a Vec cannot fail.
    w.write_record(["title", "username", "password", "url", "notes", "totp"])
        .expect("write to Vec");
    for item in vault.items() {
        w.write_record([
            item.title.as_str(),
            value(item, "username", FieldKind::Email),
            value(item, "password", FieldKind::Password),
            value(item, "url", FieldKind::Url),
            value(item, "notes", FieldKind::Notes),
            value(item, "totp", FieldKind::Totp),
        ])
        .expect("write to Vec");
    }
    PlaintextExport(w.into_inner().expect("flush to Vec"))
}
