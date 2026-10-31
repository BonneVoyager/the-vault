//! Plaintext CSV export (`02-core-api.md` "import / export").

use secrecy::ExposeSecret;
use zeroize::{Zeroize, Zeroizing};

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

/// The value of the first field named `name` (ASCII case-insensitive), else the first field
/// of `kind`, else empty. [`FieldKind::Section`] headings are skipped on both lookups: a
/// section named `notes` is a heading, not the notes.
fn value<'a>(item: &'a Item, name: &str, kind: FieldKind) -> &'a str {
    let mut fields = item.fields.iter().filter(|f| f.kind != FieldKind::Section);
    fields
        .clone()
        .find(|f| f.name.eq_ignore_ascii_case(name))
        .or_else(|| fields.find(|f| f.kind == kind))
        .map_or("", |f| f.value.expose_secret().as_str())
}

/// Characters that make a spreadsheet interpret a cell as a formula or a continuation of one
/// (OWASP "CSV Injection": `=`, `+`, `-`, `@`, tab, carriage return).
pub(crate) fn is_formula_trigger(c: char) -> bool {
    matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r')
}

/// `true` if `cell` is a formula trigger behind zero or more leading `'`: the shape the
/// export prefixes with one more quote and the import strips one quote from. Shared with
/// [`crate::import::import_csv`] so the two stay exact inverses.
pub(crate) fn trigger_behind_quotes(cell: &str) -> bool {
    cell.trim_start_matches('\'')
        .starts_with(is_formula_trigger)
}

/// Neutralise a cell for a spreadsheet: a leading formula trigger gets a `'` prefix (OWASP
/// guidance; the quote makes Excel/Numbers/Sheets treat the cell as text). A cell that is a
/// trigger behind one or more quotes already (`'=x`, `''=x`, ...) gets one more quote, so
/// that `import_csv`, which strips exactly one quote from that shape, restores the original
/// instead of eating the user's own quote. Everything else is returned unchanged.
fn neutralise(cell: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(cell.len() + 1));
    if trigger_behind_quotes(cell) {
        out.push('\'');
    }
    out.push_str(cell);
    out
}

/// Columns: `title,username,password,url,notes,totp`. Every live item is one row; a column is
/// empty when the item has no matching field. (Item categories were removed on 2026-10-30, so
/// there is no longer a "non-login" gate on the credential columns.) Section headings
/// ([`FieldKind::Section`]) are never exported.
///
/// Every cell whose first character is `=`, `+`, `-`, `@`, tab or carriage return is written
/// with a leading `'` so a spreadsheet opening the export cannot execute it as a formula
/// (CSV injection). [`crate::import::import_csv`] strips that quote again, so an export
/// imported back yields the original values.
pub fn export_csv(vault: &UnlockedVault) -> PlaintextExport {
    let mut w = csv::Writer::from_writer(Vec::new());
    // Writing to a Vec cannot fail.
    w.write_record(["title", "username", "password", "url", "notes", "totp"])
        .expect("write to Vec");
    for item in vault.items() {
        let cells = [
            neutralise(item.title.as_str()),
            neutralise(value(item, "username", FieldKind::Email)),
            neutralise(value(item, "password", FieldKind::Password)),
            neutralise(value(item, "url", FieldKind::Url)),
            neutralise(value(item, "notes", FieldKind::Notes)),
            neutralise(value(item, "totp", FieldKind::Totp)),
        ];
        w.write_record(cells.iter().map(|c| c.as_str()))
            .expect("write to Vec");
    }
    PlaintextExport(w.into_inner().expect("flush to Vec"))
}
