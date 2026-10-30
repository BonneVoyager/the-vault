//! CSV, 1PUX and optional KeePass import (`02-core-api.md` "import / export").

#[cfg(feature = "kdbx")]
mod kdbx;
#[cfg(feature = "kdbx")]
pub use kdbx::import_kdbx;

use secrecy::SecretString;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::item::{Field, FieldKind, HistoryEntry, Item, ItemKind, Millis};

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("CSV error: {0}")]
    Csv(String),
    #[error("missing CSV column: {0}")]
    MissingColumn(String),
    /// Unreadable archive or JSON. Never contains secret values.
    #[error("malformed import: {0}")]
    Malformed(String),
    #[error(
        "Could not open the KeePass database. Check its password and key file. The file may be damaged or use unsupported encryption."
    )]
    KdbxCredentials,
}

/// Column names (matched case-insensitively against the header) for each item part.
///
/// An empty name means "not mapped". `title` must be mapped. With `has_header == false` the
/// names are zero-based column indices such as `"0"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvMapping {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: Option<String>,
    pub has_header: bool,
}

impl Default for CsvMapping {
    fn default() -> Self {
        Self {
            title: "title".to_owned(),
            username: "username".to_owned(),
            password: "password".to_owned(),
            url: "url".to_owned(),
            notes: "notes".to_owned(),
            totp: Some("totp".to_owned()),
            has_header: true,
        }
    }
}

fn resolve(name: &str, headers: Option<&csv::StringRecord>) -> Result<Option<usize>, ImportError> {
    if name.is_empty() {
        return Ok(None);
    }
    let missing = || ImportError::MissingColumn(name.to_owned());
    match headers {
        Some(h) => h
            .iter()
            .position(|c| c.trim().eq_ignore_ascii_case(name.trim()))
            .map(Some)
            .ok_or_else(missing),
        None => name
            .trim()
            .parse::<usize>()
            .map(Some)
            .map_err(|_| missing()),
    }
}

/// Each row becomes a `login` item with a fresh id. Only non-empty mapped cells become fields.
pub fn import_csv(
    bytes: &[u8],
    mapping: &CsvMapping,
    device_id: Uuid,
    now: Millis,
) -> Result<Vec<Item>, ImportError> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(mapping.has_header)
        .flexible(true)
        .from_reader(bytes);
    let headers = if mapping.has_header {
        Some(
            rdr.headers()
                .map_err(|e| ImportError::Csv(e.to_string()))?
                .clone(),
        )
    } else {
        None
    };
    let h = headers.as_ref();
    let title_col = resolve(&mapping.title, h)?
        .ok_or_else(|| ImportError::MissingColumn("title".to_owned()))?;
    let parts = [
        ("username", FieldKind::Text, resolve(&mapping.username, h)?),
        (
            "password",
            FieldKind::Password,
            resolve(&mapping.password, h)?,
        ),
        ("url", FieldKind::Url, resolve(&mapping.url, h)?),
        ("notes", FieldKind::Notes, resolve(&mapping.notes, h)?),
        (
            "totp",
            FieldKind::Totp,
            match &mapping.totp {
                Some(n) => resolve(n, h)?,
                None => None,
            },
        ),
    ];

    let mut items = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| ImportError::Csv(e.to_string()))?;
        let mut item = Item::new(
            ItemKind::Login,
            rec.get(title_col).unwrap_or(""),
            device_id,
            now,
        );
        for (name, kind, col) in &parts {
            let value = col.and_then(|c| rec.get(c)).unwrap_or("");
            if !value.is_empty() {
                item.fields.push(Field::new(
                    *name,
                    *kind,
                    SecretString::new(value.to_owned()),
                    now,
                ));
            }
        }
        items.push(item);
    }
    Ok(items)
}

// ---------------------------------------------------------------------------------------------
// 1PUX
// ---------------------------------------------------------------------------------------------

const MAX_HISTORY: usize = 10;
/// Upper bound on the decompressed size of `export.data` (zip-bomb guard).
const MAX_EXPORT_DATA: u64 = 64 * 1024 * 1024;

fn malformed(msg: &str) -> ImportError {
    ImportError::Malformed(msg.to_owned())
}

fn str_of<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

fn arr_of<'a>(v: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    v.get(key)
        .and_then(|x| x.as_array())
        .map_or(&[][..], Vec::as_slice)
}

/// Makes `name` unique among `item.fields` by suffixing ` (2)`, ` (3)`, ...
fn unique_name(item: &Item, name: &str) -> String {
    if item.field(name).is_none() {
        return name.to_owned();
    }
    (2u32..)
        .map(|n| format!("{name} ({n})"))
        .find(|c| item.field(c).is_none())
        .expect("unbounded range")
}

fn push_field(
    item: &mut Item,
    name: &str,
    kind: FieldKind,
    value: &str,
    section: Option<&str>,
    now: Millis,
) {
    let name = unique_name(item, name);
    let mut f = Field::new(name, kind, SecretString::new(value.to_owned()), now);
    f.section = section.filter(|s| !s.is_empty()).map(str::to_owned);
    item.fields.push(f);
}

/// `202912` -> `12/2029`. Anything unparseable is kept as given.
fn format_month_year(v: &serde_json::Value) -> Option<String> {
    let n = v
        .as_i64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))?;
    let (year, month) = (n / 100, n % 100);
    if (1..=12).contains(&month) && year > 0 {
        Some(format!("{month:02}/{year:04}"))
    } else {
        Some(n.to_string())
    }
}

/// Unix seconds -> `YYYY-MM-DD` (proleptic Gregorian, UTC).
fn format_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Maps a 1PUX section value object (`{"concealed": "..."}`) to a kind and string.
fn section_value(
    value: &serde_json::Value,
    name: &str,
) -> Option<(String, FieldKind, Zeroizing<String>)> {
    let obj = value.as_object()?;
    let (key, v) = obj.iter().find(|(_, v)| !v.is_null())?;
    let text = |v: &serde_json::Value| {
        Zeroizing::new(match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    };
    let (name, kind, val) = match key.as_str() {
        "concealed" => (name.to_owned(), FieldKind::Password, text(v)),
        "totp" => (name.to_owned(), FieldKind::Totp, text(v)),
        "url" => (name.to_owned(), FieldKind::Url, text(v)),
        "email" => (name.to_owned(), FieldKind::Email, text(v)),
        "monthYear" => (
            name.to_owned(),
            FieldKind::MonthYear,
            Zeroizing::new(format_month_year(v)?),
        ),
        "date" => (
            name.to_owned(),
            FieldKind::Date,
            Zeroizing::new(format_date(
                v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))?,
            )),
        ),
        "creditCardNumber" => ("number".to_owned(), FieldKind::Text, text(v)),
        _ => (name.to_owned(), FieldKind::Text, text(v)),
    };
    if val.is_empty() {
        None
    } else {
        Some((name, kind, val))
    }
}

fn convert_1pux_item(src: &serde_json::Value, device_id: Uuid, now: Millis) -> Item {
    let overview = src.get("overview").unwrap_or(&serde_json::Value::Null);
    let details = src.get("details").unwrap_or(&serde_json::Value::Null);
    let kind = match str_of(src, "categoryUuid") {
        "003" => ItemKind::Note,
        "002" => ItemKind::Card,
        "004" => ItemKind::Identity,
        _ => ItemKind::Login,
    };
    let title = match str_of(overview, "title").trim() {
        "" => "Untitled",
        t => t,
    };
    let mut item = Item::new(kind, title, device_id, now);
    item.favorite = src.get("favIndex").and_then(|v| v.as_u64()).unwrap_or(0) > 0;
    item.tags = arr_of(overview, "tags")
        .iter()
        .filter_map(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect();

    for lf in arr_of(details, "loginFields") {
        let value = str_of(lf, "value");
        if value.is_empty() {
            continue;
        }
        match str_of(lf, "designation") {
            "username" => push_field(&mut item, "username", FieldKind::Text, value, None, now),
            "password" => push_field(&mut item, "password", FieldKind::Password, value, None, now),
            _ => {}
        }
    }
    let url = str_of(overview, "url");
    if !url.is_empty() {
        push_field(&mut item, "url", FieldKind::Url, url, None, now);
    }
    let notes = str_of(details, "notesPlain");
    if !notes.is_empty() {
        push_field(&mut item, "notes", FieldKind::Notes, notes, None, now);
    }

    for section in arr_of(details, "sections") {
        let title = str_of(section, "title");
        for f in arr_of(section, "fields") {
            let name = match str_of(f, "title") {
                "" => str_of(f, "id"),
                t => t,
            };
            let name = if name.is_empty() { "field" } else { name };
            if let Some((name, kind, val)) = f.get("value").and_then(|v| section_value(v, name)) {
                push_field(&mut item, &name, kind, &val, Some(title), now);
            }
        }
    }

    let mut hist: Vec<(u64, Zeroizing<String>)> = arr_of(details, "passwordHistory")
        .iter()
        .filter_map(|h| {
            let v = str_of(h, "value");
            (!v.is_empty()).then(|| {
                let t = h.get("time").and_then(|t| t.as_u64()).unwrap_or(0);
                (t.saturating_mul(1000), Zeroizing::new(v.to_owned()))
            })
        })
        .collect();
    hist.sort_by_key(|h| std::cmp::Reverse(h.0));
    hist.truncate(MAX_HISTORY);
    item.history = hist
        .into_iter()
        .map(|(replaced_at, v)| HistoryEntry {
            value: SecretString::new(v.as_str().to_owned()),
            replaced_at,
        })
        .collect();
    item
}

/// Imports a 1Password `.1pux` archive (zip containing `export.data` JSON).
///
/// Archived items (`state != "active"`) are skipped. Imported items get fresh ids and
/// `modified_at = now` on the item and every field. Unknown keys are ignored. Errors never
/// contain item values.
pub fn import_1pux(bytes: &[u8], device_id: Uuid, now: Millis) -> Result<Vec<Item>, ImportError> {
    use std::io::Read;

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|_| malformed("not a valid zip archive"))?;
    let file = zip
        .by_name("export.data")
        .map_err(|_| malformed("missing export.data"))?;
    let mut data = Zeroizing::new(Vec::new());
    file.take(MAX_EXPORT_DATA + 1)
        .read_to_end(&mut data)
        .map_err(|_| malformed("cannot read export.data"))?;
    if data.len() as u64 > MAX_EXPORT_DATA {
        return Err(malformed("export.data too large"));
    }
    // NOTE: the `serde_json::Value` tree cannot be zeroized on drop (same limitation as the CBOR
    // tree in format.rs); only the raw buffer and intermediate strings are wiped.
    let root: serde_json::Value =
        serde_json::from_slice(&data).map_err(|_| malformed("export.data is not valid JSON"))?;

    let mut items = Vec::new();
    for account in arr_of(&root, "accounts") {
        for vault in arr_of(account, "vaults") {
            for src in arr_of(vault, "items") {
                if str_of(src, "state") != "active" {
                    continue;
                }
                items.push(convert_1pux_item(src, device_id, now));
            }
        }
    }
    Ok(items)
}
