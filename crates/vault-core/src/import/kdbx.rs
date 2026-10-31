//! KDBX 3/4 parsing is delegated to keepass-rs; this module only maps its data model.
//! The dependency zeroizes credentials and protected fields. Its XML/unprotected
//! field allocations are not guaranteed to be wiped (as with the 1PUX JSON parser).
//!
//! Before handing the bytes to keepass-rs the outer header is walked once here
//! ([`check_outer_header`]). KDF parameters live in that *unauthenticated* header and
//! keepass-rs runs the KDF before any key check, so a crafted file could demand
//! terabytes of Argon2 memory (rust-argon2 aborts the process on allocation failure) or
//! hours of AES rounds. The walk mirrors keepass-rs 0.17.0 byte-for-byte
//! (`format/mod.rs` `DatabaseVersion::parse`, `format/kdbx3.rs` `parse_outer_header`,
//! `format/kdbx4/parse.rs` `parse_outer_header`, `format/variant_dictionary.rs`
//! `VariantDictionary::parse`, `config.rs` `TryFrom<VariantDictionary> for (KdfConfig,
//! Vec<u8>)`) so the values it bounds are exactly the ones keepass-rs would use. It also
//! rejects the short fixed-width entries that keepass-rs reads with panicking
//! `byteorder` calls.

use std::io::Cursor;

use keepass::{Database, DatabaseKey, db::Entry};
use secrecy::{ExposeSecret as _, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ImportError, TAG_LOGIN, add_template_tag};
use crate::item::{Field, FieldKind, HistoryEntry, Item, Millis};
use crate::totp::Totp;
use crate::vault::HISTORY_CAP;

/// Upper bound on KDBX3 / AES-KDF `transform_rounds` (header TLV 6, KDBX4 key `R`).
const MAX_AES_ROUNDS: u64 = 1 << 26;
/// Upper bound on Argon2 memory, in bytes as stored in the file (KDBX4 key `M`).
const MAX_ARGON2_MEMORY: u64 = 1 << 30;
/// Upper bound on Argon2 iterations (KDBX4 key `I`).
const MAX_ARGON2_ITERATIONS: u64 = 64;
/// Upper bound on Argon2 parallelism (KDBX4 key `P`).
const MAX_ARGON2_PARALLELISM: u32 = 16;

const KDBX_MAGIC: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const KDBX_SIGNATURE_2: u32 = 0xb54b_fb67;
const VARIANT_DICTIONARY_VERSION: u16 = 0x100;

// KDF UUIDs from keepass-rs `config.rs`; only these four are ever accepted downstream.
const KDF_AES_KDBX3: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];
const KDF_AES_KDBX4: [u8; 16] = [
    0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64, 0x82, 0x38,
];
const KDF_ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const KDF_ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

/// KeePass 2.x native and KeeTrayTOTP field names folded into one `totp` field.
const NATIVE_TOTP_FIELDS: [&str; 6] = [
    "TimeOtp-Secret-Base32",
    "TimeOtp-Length",
    "TimeOtp-Period",
    "TimeOtp-Algorithm",
    "TOTP Seed",
    "TOTP Settings",
];

/// Import entries with fresh IDs and importer-supplied stamps (`created_at` keeps the entry's
/// KeePass creation time when it has one). Group paths become tags; recycle-bin entries are
/// excluded. Attachments, icons and auto-type settings
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
    check_outer_header(bytes)?;
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

fn malformed(what: &str) -> ImportError {
    ImportError::Malformed(what.to_owned())
}

/// `len` bytes at `*pos`, advancing; `Malformed` instead of a panic on overflow or EOF.
fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], ImportError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| malformed("truncated KeePass header"))?;
    let slice = bytes
        .get(*pos..end)
        .ok_or_else(|| malformed("truncated KeePass header"))?;
    *pos = end;
    Ok(slice)
}

fn le_u16(bytes: &[u8]) -> Option<u16> {
    bytes.get(..2)?.try_into().ok().map(u16::from_le_bytes)
}

fn le_u32(bytes: &[u8]) -> Option<u32> {
    bytes.get(..4)?.try_into().ok().map(u32::from_le_bytes)
}

fn le_u64(bytes: &[u8]) -> Option<u64> {
    bytes.get(..8)?.try_into().ok().map(u64::from_le_bytes)
}

/// Validate magic, signature and major version (keepass-rs `format/mod.rs` 56-89) and walk
/// the outer header TLVs (KDBX3: `type u8, len u16 LE`, `format/kdbx3.rs` 46-118; KDBX4:
/// `type u8, len u32 LE`, `format/kdbx4/parse.rs` 163-224) up to the END entry. Bounds the
/// KDF parameters, rejects KDF UUIDs keepass-rs does not know, and rejects fixed-width
/// entries shorter than keepass-rs's unchecked `byteorder` reads.
fn check_outer_header(bytes: &[u8]) -> Result<(), ImportError> {
    let mut pos = 0;
    let magic = take(bytes, &mut pos, 4)?;
    let signature = le_u32(take(bytes, &mut pos, 4)?);
    let _minor = take(bytes, &mut pos, 2)?;
    let major = le_u16(take(bytes, &mut pos, 2)?);
    let kdbx4 = match (magic, signature, major) {
        (m, Some(KDBX_SIGNATURE_2), Some(3)) if m == KDBX_MAGIC => false,
        (m, Some(KDBX_SIGNATURE_2), Some(4)) if m == KDBX_MAGIC => true,
        _ => return Err(malformed("expected a KDBX 3 or 4 database")),
    };
    let mut kdf_seen = false;
    loop {
        let kind = take(bytes, &mut pos, 1)?[0];
        let len = if kdbx4 {
            le_u32(take(bytes, &mut pos, 4)?).map(|n| n as usize)
        } else {
            le_u16(take(bytes, &mut pos, 2)?).map(usize::from)
        };
        let body = take(bytes, &mut pos, len.unwrap_or(usize::MAX))?;
        match (kdbx4, kind) {
            (_, 0) => break,
            // COMMENT, CIPHERID, MASTERSEED, ENCRYPTIONIV: both versions, variable length.
            (_, 1 | 2 | 4 | 7) => {}
            // COMPRESSIONFLAGS (both) and KDBX3 INNERRANDOMSTREAMID: `read_u32`.
            (_, 3) | (false, 10) if body.len() < 4 => {
                return Err(malformed("truncated KeePass header entry"));
            }
            (_, 3) | (false, 10) => {}
            // KDBX3 TRANSFORMSEED, PROTECTEDSTREAMKEY, STREAMSTARTBYTES.
            (false, 5 | 8 | 9) => {}
            // KDBX3 TRANSFORMROUNDS: `read_u64`, always AES-KDF.
            (false, 6) => {
                let rounds =
                    le_u64(body).ok_or_else(|| malformed("truncated KeePass header entry"))?;
                check_aes_rounds(rounds)?;
                kdf_seen = true;
            }
            // KDBX4 KDF parameters VariantDictionary.
            (true, 11) => {
                check_kdf_parameters(body)?;
                kdf_seen = true;
            }
            // KDBX4 public custom data: parsed by keepass-rs, so it must be well-formed.
            (true, 12) => {
                parse_variant_dictionary(body)?;
            }
            _ => return Err(malformed("unexpected KeePass header entry")),
        }
    }
    if !kdf_seen {
        return Err(malformed("KeePass header is missing KDF parameters"));
    }
    Ok(())
}

fn check_aes_rounds(rounds: u64) -> Result<(), ImportError> {
    if rounds > MAX_AES_ROUNDS {
        return Err(malformed("KDF parameters exceed safe limits"));
    }
    Ok(())
}

/// Typed VariantDictionary values that matter here; everything else is `Other`.
enum Variant<'a> {
    U32(u32),
    U64(u64),
    Bytes(&'a [u8]),
    Other,
}

/// Mirror of keepass-rs `VariantDictionary::parse` (`format/variant_dictionary.rs` 51-117):
/// `version u16 == 0x0100`, then `type u8, key_len u32, key, value_len u32, value` while
/// `pos + 9 < len`, then a `0x00` terminator. Fixed-width values shorter than their type
/// are rejected (keepass-rs would panic in `byteorder`); longer ones use their leading bytes
/// exactly as keepass-rs does. Later duplicates win, matching its `HashMap::insert`.
fn parse_variant_dictionary(buf: &[u8]) -> Result<Vec<(&[u8], Variant<'_>)>, ImportError> {
    let bad = || malformed("malformed KeePass header dictionary");
    let mut pos = 0;
    if le_u16(take(buf, &mut pos, 2)?) != Some(VARIANT_DICTIONARY_VERSION) {
        return Err(bad());
    }
    let mut entries = Vec::new();
    while pos + 9 < buf.len() {
        let kind = take(buf, &mut pos, 1)?[0];
        let key_len = le_u32(take(buf, &mut pos, 4)?).ok_or_else(bad)? as usize;
        let key = take(buf, &mut pos, key_len)?;
        let value_len = le_u32(take(buf, &mut pos, 4)?).ok_or_else(bad)? as usize;
        let value = take(buf, &mut pos, value_len)?;
        let value = match kind {
            0x04 => Variant::U32(le_u32(value).ok_or_else(bad)?),
            0x05 => Variant::U64(le_u64(value).ok_or_else(bad)?),
            0x0c if value.len() < 4 => return Err(bad()),
            0x0d if value.len() < 8 => return Err(bad()),
            0x42 => Variant::Bytes(value),
            0x08 | 0x0c | 0x0d | 0x18 => Variant::Other,
            _ => return Err(bad()),
        };
        entries.push((key, value));
    }
    if pos == buf.len() || buf.get(pos) != Some(&0) {
        return Err(bad());
    }
    Ok(entries)
}

/// Bound the KDBX4 KDF parameters (keepass-rs `config.rs` 403-462: `$UUID` selects the KDF;
/// Argon2d/Argon2id read `M` u64 bytes, `I` u64, `P` u32; AES reads `R` u64).
fn check_kdf_parameters(buf: &[u8]) -> Result<(), ImportError> {
    let entries = parse_variant_dictionary(buf)?;
    let last = |name: &str| {
        entries
            .iter()
            .rev()
            .find(|(key, _)| *key == name.as_bytes())
            .map(|(_, value)| value)
    };
    let missing = || malformed("KeePass header is missing KDF parameters");
    let Some(Variant::Bytes(uuid)) = last("$UUID") else {
        return Err(missing());
    };
    if *uuid == KDF_ARGON2D || *uuid == KDF_ARGON2ID {
        let (Some(Variant::U64(memory)), Some(Variant::U64(iterations)), Some(Variant::U32(lanes))) =
            (last("M"), last("I"), last("P"))
        else {
            return Err(missing());
        };
        if *memory > MAX_ARGON2_MEMORY
            || *iterations > MAX_ARGON2_ITERATIONS
            || *lanes > MAX_ARGON2_PARALLELISM
        {
            return Err(malformed("KDF parameters exceed safe limits"));
        }
        Ok(())
    } else if *uuid == KDF_AES_KDBX3 || *uuid == KDF_AES_KDBX4 {
        let Some(Variant::U64(rounds)) = last("R") else {
            return Err(missing());
        };
        check_aes_rounds(*rounds)
    } else {
        Err(malformed("unsupported KeePass key derivation function"))
    }
}

fn convert(entry: &Entry, device_id: Uuid, now: Millis) -> Item {
    let title = entry.get_title().unwrap_or("Untitled");
    let mut item = Item::new(title, device_id, now);
    // KeePass `CreationTime` when the entry has one (representable and after the Unix
    // epoch; a zero stamp means "unknown", as in the 1PUX path), else `Item::new`'s `now`.
    if let Some(created) = entry
        .times
        .creation
        .and_then(|time| u64::try_from(time.and_utc().timestamp_millis()).ok())
        .filter(|ms| *ms > 0)
    {
        item.created_at = Some(created);
    }
    item.tags = entry.tags.clone();
    // Every KeePass entry is a login (item kinds were removed on 2026-10-30; the template tag
    // replaces them).
    add_template_tag(&mut item, TAG_LOGIN);
    let totp = native_totp(entry, title);
    let mut fields: Vec<_> = entry
        .fields
        .iter()
        .filter(|(name, _)| {
            name.as_str() != "Title"
                && !(totp.is_some() && NATIVE_TOTP_FIELDS.contains(&name.as_str()))
        })
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
        push_field(
            &mut item,
            name,
            kind,
            SecretString::new(value.get().clone()),
            now,
        );
    }
    if let Some(uri) = totp {
        push_field(&mut item, "totp", FieldKind::Totp, uri, now);
    }
    if let Some(history) = &entry.history {
        let current = entry.get_password();
        let mut versions: Vec<HistoryEntry> = history
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
        versions.sort_by_key(|entry| std::cmp::Reverse(entry.replaced_at));
        // KeePass snapshots the whole entry on every edit, so most versions repeat the
        // password. Keep the newest copy of each distinct value, never the current one.
        let mut kept: Vec<HistoryEntry> = Vec::new();
        for version in versions {
            let value = version.value.expose_secret().as_str();
            if Some(value) == current || kept.iter().any(|k| k.value.expose_secret() == value) {
                continue;
            }
            kept.push(version);
            if kept.len() == HISTORY_CAP {
                break;
            }
        }
        item.history = kept;
    }
    item
}

/// Append a field, suffixing its name with ` (2)`, ` (3)`, … on a collision.
fn push_field(item: &mut Item, name: &str, kind: FieldKind, value: SecretString, now: Millis) {
    let mut unique = name.to_owned();
    let mut suffix = 2;
    while item.fields.iter().any(|field| field.name == unique) {
        unique = format!("{name} ({suffix})");
        suffix += 1;
    }
    item.fields.push(Field::new(unique, kind, value, now));
}

/// KeePass 2.x native TOTP (`TimeOtp-Secret-Base32` plus optional `TimeOtp-Length`,
/// `TimeOtp-Period`, `TimeOtp-Algorithm` = `HMAC-SHA-1|256|512`) or KeeTrayTOTP
/// (`TOTP Seed` plus `TOTP Settings` = `period;digits`) as a canonical otpauth URI labelled
/// with the entry title. `None` when absent or not representable (e.g. Steam digits); the
/// raw fields are then kept as ordinary custom fields.
fn native_totp(entry: &Entry, title: &str) -> Option<SecretString> {
    let (secret, digits, period, algorithm) =
        if let Some(secret) = entry.get("TimeOtp-Secret-Base32") {
            let algorithm = match entry.get("TimeOtp-Algorithm").map(str::trim) {
                None | Some("" | "HMAC-SHA-1") => "SHA1",
                Some("HMAC-SHA-256") => "SHA256",
                Some("HMAC-SHA-512") => "SHA512",
                Some(_) => return None,
            };
            let digits = entry.get("TimeOtp-Length").unwrap_or("6");
            let period = entry.get("TimeOtp-Period").unwrap_or("30");
            (secret, digits, period, algorithm)
        } else {
            let secret = entry.get("TOTP Seed")?;
            let (period, digits) = entry
                .get("TOTP Settings")
                .and_then(|settings| settings.split_once(';'))
                .unwrap_or(("30", "6"));
            (secret, digits, period, "SHA1")
        };
    let digits: u32 = digits.trim().parse().ok()?;
    let period: u32 = period.trim().parse().ok()?;
    let uri = Zeroizing::new(format!(
        "otpauth://totp/{}?secret={}&digits={digits}&period={period}&algorithm={algorithm}",
        percent_encode(title).as_str(),
        percent_encode(secret).as_str(),
    ));
    Totp::parse_uri(&uri).ok().map(|totp| totp.to_uri())
}

/// RFC 3986 unreserved characters pass through; everything else is `%XX`.
fn percent_encode(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
